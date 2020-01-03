// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netlink

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// alignUp rounds a length up to an alignment.
//
// Preconditions: align is a power of two.
func alignUp(length int, align uint) int {
	return (length + int(align) - 1) &^ (int(align) - 1)
}

// Message contains a complete serialized netlink message.
type Message struct {
	hdr linux.NetlinkMessageHeader
	buf []byte
}

// NewMessage creates a new Message containing the passed header.
//
// The header length will be updated by Finalize.
func NewMessage(hdr linux.NetlinkMessageHeader) *Message {
	return &Message{
		hdr: hdr,
		buf: binary.Marshal(nil, usermem.ByteOrder, hdr),
	}
}

// ParseMessage parses the first message seen at buf, returning the rest of the
// buffer. If message is malformed, ok of false is returned.
func ParseMessage(buf []byte) (msg *Message, rest []byte, ok bool) {
	if len(buf) < linux.NetlinkMessageHeaderSize {
		return nil, nil, false
	}

	var hdr linux.NetlinkMessageHeader
	binary.Unmarshal(buf[:linux.NetlinkMessageHeaderSize], usermem.ByteOrder, &hdr)

	if hdr.Length < linux.NetlinkMessageHeaderSize || uint64(hdr.Length) > uint64(len(buf)) {
		return nil, nil, false
	}

	// Next message offset.
	next := alignUp(int(hdr.Length), linux.NLMSG_ALIGNTO)
	if next >= len(buf)-1 {
		next = len(buf) - 1
	}

	return &Message{
		hdr: hdr,
		buf: buf[:hdr.Length],
	}, buf[next:], true
}

// Header returns the header of this message.
func (m *Message) Header() linux.NetlinkMessageHeader {
	return m.hdr
}

// GetData unmarshals the payload message header from this netlink message, and
// returns the attributes portion.
func (m *Message) GetData(msg interface{}) (AttrsView, bool) {
	size := binary.Size(msg)
	aligned := alignUp(linux.NetlinkMessageHeaderSize+int(size), linux.NLMSG_ALIGNTO)
	if m.hdr.Length < uint32(aligned) {
		return nil, false
	}
	data := m.buf[linux.NetlinkMessageHeaderSize:]
	binary.Unmarshal(data[:size], usermem.ByteOrder, msg)
	return AttrsView(data[size:]), true
}

// Finalize returns the []byte containing the entire message, with the total
// length set in the message header. The Message must not be modified after
// calling Finalize.
func (m *Message) Finalize() []byte {
	// Update length, which is the first 4 bytes of the header.
	usermem.ByteOrder.PutUint32(m.buf, uint32(len(m.buf)))

	// Align the message. Note that the message length in the header (set
	// above) is the useful length of the message, not the total aligned
	// length. See net/netlink/af_netlink.c:__nlmsg_put.
	aligned := alignUp(len(m.buf), linux.NLMSG_ALIGNTO)
	m.putZeros(aligned - len(m.buf))
	return m.buf
}

// putZeros adds n zeros to the message.
func (m *Message) putZeros(n int) {
	for n > 0 {
		m.buf = append(m.buf, 0)
		n--
	}
}

// Put serializes v into the message.
func (m *Message) Put(v interface{}) {
	m.buf = binary.Marshal(m.buf, usermem.ByteOrder, v)
}

// PutAttr adds v to the message as a netlink attribute.
//
// Preconditions: The serialized attribute (linux.NetlinkAttrHeaderSize +
// binary.Size(v) fits in math.MaxUint16 bytes.
func (m *Message) PutAttr(atype uint16, v interface{}) {
	l := linux.NetlinkAttrHeaderSize + int(binary.Size(v))
	if l > math.MaxUint16 {
		panic(fmt.Sprintf("attribute too large: %d", l))
	}

	m.Put(linux.NetlinkAttrHeader{
		Type:   atype,
		Length: uint16(l),
	})
	m.Put(v)

	// Align the attribute.
	aligned := alignUp(l, linux.NLA_ALIGNTO)
	m.putZeros(aligned - l)
}

// PutAttrString adds s to the message as a netlink attribute.
func (m *Message) PutAttrString(atype uint16, s string) {
	l := linux.NetlinkAttrHeaderSize + len(s) + 1
	m.Put(linux.NetlinkAttrHeader{
		Type:   atype,
		Length: uint16(l),
	})

	// String + NUL-termination.
	m.Put([]byte(s))
	m.putZeros(1)

	// Align the attribute.
	aligned := alignUp(l, linux.NLA_ALIGNTO)
	m.putZeros(aligned - l)
}

// MessageSet contains a series of netlink messages.
type MessageSet struct {
	// Multi indicates that this a multi-part message, to be terminated by
	// NLMSG_DONE. NLMSG_DONE is sent even if the set contains only one
	// Message.
	//
	// If Multi is set, all added messages will have NLM_F_MULTI set.
	Multi bool

	// PortID is the destination port for all messages.
	PortID int32

	// Seq is the sequence counter for all messages in the set.
	Seq uint32

	// Messages contains the messages in the set.
	Messages []*Message
}

// NewMessageSet creates a new MessageSet.
//
// portID is the destination port to set as PortID in all messages.
//
// seq is the sequence counter to set as seq in all messages in the set.
func NewMessageSet(portID int32, seq uint32) *MessageSet {
	return &MessageSet{
		PortID: portID,
		Seq:    seq,
	}
}

// AddMessage adds a new message to the set and returns it for further
// additions.
//
// The passed header will have Seq, PortID and the multi flag set
// automatically.
func (ms *MessageSet) AddMessage(hdr linux.NetlinkMessageHeader) *Message {
	hdr.Seq = ms.Seq
	hdr.PortID = uint32(ms.PortID)
	if ms.Multi {
		hdr.Flags |= linux.NLM_F_MULTI
	}

	m := NewMessage(hdr)
	ms.Messages = append(ms.Messages, m)
	return m
}

// AttrsView is a view into the attributes portion of a netlink message.
type AttrsView []byte

// Empty returns whether there is no attribute left in v.
func (v AttrsView) Empty() bool {
	return len(v) == 0
}

// Next parses first netlink attribute at the beginning of v.
func (v AttrsView) Next() (hdr linux.NetlinkAttrHeader, value []byte, rest AttrsView, ok bool) {
	hdrSize := linux.NetlinkAttrHeaderSize
	if len(v) < hdrSize {
		return linux.NetlinkAttrHeader{}, nil, nil, false
	}
	binary.Unmarshal(v[:hdrSize], usermem.ByteOrder, &hdr)

	aligned := alignUp(int(hdr.Length), linux.NLA_ALIGNTO)
	if len(v) < aligned {
		return linux.NetlinkAttrHeader{}, nil, nil, false
	}
	return hdr, v[hdrSize:int(hdr.Length)], v[aligned:], true
}

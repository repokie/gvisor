// Copyright 2020 The gVisor Authors.
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

package dev

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

var zeroMAC [6]byte

const (
	netTunDevMajor = 10
	netTunDevMinor = 200
)

// +stateify savable
type netTunInodeOperations struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopAllocate         `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes
}

var _ fs.InodeOperations = (*netTunInodeOperations)(nil)

func newNetTunDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *netTunInodeOperations {
	return &netTunInodeOperations{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(mode), linux.TMPFS_MAGIC),
	}
}

func (iops *netTunInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &netTunFileOperations{}), nil
}

// +stateify savable
type netTunFileOperations struct {
	fsutil.FileNoSeek               `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	waiter.Queue

	mu           sync.RWMutex
	stack        *netstack.Stack
	endpoint     *tunEndpoint
	notifyHandle *channel.NotificationHandle
	flags        uint16
}

var _ fs.FileOperations = (*netTunFileOperations)(nil)

// Release implements fs.FileOperations.Release.
func (fops *netTunFileOperations) Release() {
	fops.mu.Lock()
	defer fops.mu.Unlock()

	// Decrease refcount if there is an endpoint associated with this file.
	if fops.endpoint != nil {
		fops.endpoint.RemoveNotify(fops.notifyHandle)
		fops.endpoint.DecRefWithDestructor(func() {
			fops.stack.Stack.RemoveNIC(fops.endpoint.nicID)
		})
	}
}

// Ioctl implements fs.FileOperations.Ioctl.
func (fops *netTunFileOperations) Ioctl(ctx context.Context, file *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	request := args[1].Uint()
	data := args[2].Pointer()

	switch request {
	case linux.TUNSETIFF:
		if t := kernel.TaskFromContext(ctx); t == nil || !t.HasCapability(linux.CAP_NET_ADMIN) {
			return 0, syserror.EPERM
		}

		var req linux.IFReq
		if _, err := usermem.CopyObjectIn(ctx, io, data, &req, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return 0, err
		}
		flags := usermem.ByteOrder.Uint16(req.Data[:])
		return 0, fops.setIff(ctx, req.Name(), flags)

	case linux.TUNGETIFF:
		req := fops.getIff()
		_, err := usermem.CopyObjectOut(ctx, io, data, &req, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err

	default:
		return 0, syserror.ENOTTY
	}
}

func (fops *netTunFileOperations) setIff(ctx context.Context, name string, flags uint16) error {
	fops.mu.Lock()
	defer fops.mu.Unlock()

	if fops.endpoint != nil {
		return syserror.EINVAL
	}

	// Input validations.
	isTun := flags&linux.IFF_TUN != 0
	isTap := flags&linux.IFF_TAP != 0
	supportedFlags := uint16(linux.IFF_TUN | linux.IFF_TAP | linux.IFF_NO_PI)
	if isTap && isTun || !isTap && !isTun || flags&^supportedFlags != 0 {
		return syserror.EINVAL
	}

	var prefix string
	if isTun {
		prefix = "tun"
	} else {
		prefix = "tap"
	}

	stack, err := getNetStack(ctx)
	if err != nil {
		return err
	}
	endpoint, err := attachOrCreateNIC(stack, name, prefix)
	if err != nil {
		return syserror.EINVAL
	}

	fops.stack = stack
	fops.endpoint = endpoint
	fops.notifyHandle = fops.endpoint.AddNotify(fops)
	fops.flags = flags
	return nil
}

func attachNIC(stack *netstack.Stack, name string) (*tunEndpoint, error) {
	nic, found := stack.Stack.GetNICByName(name)
	if !found {
		return nil, syserror.ENODEV
	}
	endpoint, ok := nic.LinkEndpoint().(*tunEndpoint)
	if !ok {
		// Not a NIC created by tun device.
		return nil, syserror.EOPNOTSUPP
	}
	if !endpoint.TryIncRef() {
		// Race detected: NIC got deleted in between.
		return nil, syserror.EAGAIN
	}
	return endpoint, nil
}

func attachOrCreateNIC(s *netstack.Stack, name, prefix string) (*tunEndpoint, error) {
	for {
		// 1. Try to attach to an existing NIC.
		if name != "" {
			endpoint, err := attachNIC(s, name)
			switch err {
			case syserror.ENODEV:
				// Device not found, creating a new one in the next step.
			case syserror.EAGAIN:
				continue
			default:
				return endpoint, err
			}
		}

		// 2. Creating a new NIC.
		id := tcpip.NICID(s.Stack.UniqueID())
		endpoint := &tunEndpoint{
			Endpoint: channel.New(1024, 1500, ""),
			nicID:    id,
			name:     name,
		}
		if endpoint.name == "" {
			endpoint.name = fmt.Sprintf("%s%d", prefix, id)
		}
		endpoint.IncRef()
		err := s.Stack.CreateNICWithOptions(endpoint.nicID, endpoint, stack.NICOptions{
			Name: endpoint.name,
		})
		switch err {
		case nil:
			return endpoint, nil
		case tcpip.ErrDuplicateNICID:
			// Race detected: A NIC has been created in between.
			continue
		default:
			return nil, syserror.EINVAL
		}
	}
}

func (fops *netTunFileOperations) getIff() linux.IFReq {
	fops.mu.RLock()
	defer fops.mu.RUnlock()

	var req linux.IFReq
	if fops.endpoint != nil {
		copy(req.IFName[:], []byte(fops.endpoint.name))
	}
	// Linux adds IFF_NOFILTER (the same value as IFF_NO_PI unfortunately) when
	// there is no sk_filter. See __tun_chr_ioctl() in net/drivers/tun.c.
	flags := fops.flags | linux.IFF_NOFILTER
	usermem.ByteOrder.PutUint16(req.Data[:], flags)
	return req
}

// Ioctl implements fs.FileOperations.Write.
func (fops *netTunFileOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}

	// Try to deliver packet and ignore bad format.
	fops.decodeAndInjectPkt(data)
	return int64(len(data)), nil
}

func (fops *netTunFileOperations) decodeAndInjectPkt(data []byte) error {
	fops.mu.RLock()
	endpoint := fops.endpoint
	fops.mu.RUnlock()
	if endpoint == nil {
		return syserror.EBADFD
	}
	if !endpoint.IsAttached() {
		return syserror.EIO
	}

	// Packet information.
	var pktInfoHdr tun.PacketInfoHeader
	if !fops.hasFlags(linux.IFF_NO_PI) {
		if len(data) < tun.PacketInfoHeaderSize {
			return syserror.EINVAL
		}
		pktInfoHdr = tun.PacketInfoHeader(data[:tun.PacketInfoHeaderSize])
		data = data[tun.PacketInfoHeaderSize:]
	}

	// Ethernet header (TAP only).
	var ethHdr header.Ethernet
	if fops.hasFlags(linux.IFF_TAP) {
		if len(data) < header.EthernetMinimumSize {
			return syserror.EINVAL
		}
		ethHdr = header.Ethernet(data[:header.EthernetMinimumSize])
		data = data[header.EthernetMinimumSize:]
	}

	// Try to determine network protocol number, default zero.
	var protocol tcpip.NetworkProtocolNumber
	switch {
	case pktInfoHdr != nil:
		protocol = pktInfoHdr.Protocol()
	case ethHdr != nil:
		protocol = ethHdr.Type()
	}

	// Try to determine remote link address, default zero.
	var remote tcpip.LinkAddress
	switch {
	case ethHdr != nil:
		remote = ethHdr.SourceAddress()
	default:
		remote = tcpip.LinkAddress(zeroMAC[:])
	}

	pkt := tcpip.PacketBuffer{
		Data: buffer.View(data).ToVectorisedView(),
	}
	if ethHdr != nil {
		pkt.LinkHeader = buffer.View(ethHdr)
	}
	endpoint.InjectLinkAddr(protocol, remote, pkt)
	return nil
}

// Ioctl implements fs.FileOperations.Read.
func (fops *netTunFileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	fops.mu.RLock()
	endpoint := fops.endpoint
	fops.mu.RUnlock()
	if endpoint == nil {
		return 0, syserror.EBADFD
	}

	for {
		info, ok := endpoint.Read()
		if !ok {
			return 0, syserror.ErrWouldBlock
		}

		v, ok := fops.encodePkt(&info)
		if !ok {
			// Ignore unsupported packet.
			continue
		}
		n, err := dst.CopyOut(ctx, v)
		if n > 0 && n < len(v) {
			// Not an error for partial copying. Packet truncated.
			err = nil
		}
		return int64(n), err
	}
}

// encodePkt encodes packet for fd side.
func (fops *netTunFileOperations) encodePkt(info *channel.PacketInfo) (buffer.View, bool) {
	var vv buffer.VectorisedView

	// Packet information.
	if !fops.hasFlags(linux.IFF_NO_PI) {
		hdr := make(tun.PacketInfoHeader, tun.PacketInfoHeaderSize)
		hdr.Encode(&tun.PacketInfoFields{
			Flags:    0,
			Protocol: info.Proto,
		})
		vv.AppendView(buffer.View(hdr))
	}

	// If the packet does not already have link layer header, and the route
	// does not exist, we can't compute it. This is possibly a raw packet, tun
	// device doesn't support this at the moment.
	if info.Pkt.LinkHeader == nil && info.Route == nil {
		return nil, false
	}

	// Ethernet header (TAP only).
	if fops.hasFlags(linux.IFF_TAP) {
		// Add ethernet header if not provided.
		if info.Pkt.LinkHeader == nil {
			hdr := &header.EthernetFields{
				SrcAddr: info.Route.LocalLinkAddress,
				DstAddr: info.Route.RemoteLinkAddress,
				Type:    info.Proto,
			}
			if hdr.SrcAddr == "" {
				hdr.SrcAddr = fops.endpoint.LinkAddress()
			}

			eth := make(header.Ethernet, header.EthernetMinimumSize)
			eth.Encode(hdr)
			vv.AppendView(buffer.View(eth))
		} else {
			vv.AppendView(info.Pkt.LinkHeader)
		}
	}

	// Append upper headers.
	vv.AppendView(buffer.View(info.Pkt.Header.View()[len(info.Pkt.LinkHeader):]))
	// Append data payload.
	vv.Append(info.Pkt.Data)

	return vv.ToView(), true
}

// Readiness implements watier.Waitable.Readiness.
func (fops *netTunFileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	if mask&waiter.EventIn != 0 {
		fops.mu.RLock()
		endpoint := fops.endpoint
		fops.mu.RUnlock()
		if endpoint != nil && endpoint.NumQueued() == 0 {
			mask &= ^waiter.EventIn
		}
	}
	return mask & (waiter.EventIn | waiter.EventOut)
}

func (fops *netTunFileOperations) hasFlags(flags uint16) bool {
	return fops.flags&flags == flags
}

// WriteNotify implements channel.Notification.WriteNotify.
func (fops *netTunFileOperations) WriteNotify() {
	fops.Notify(waiter.EventIn)
}

func getNetStack(ctx context.Context) (*netstack.Stack, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		return nil, syserror.EINVAL
	}
	s, ok := t.NetworkContext().(*netstack.Stack)
	if !ok {
		return nil, syserror.EINVAL
	}
	return s, nil
}

// tunEndpoint is the link endpoint for the NIC created by the tun device.
//
// It is ref-counted as multiple opening files can attach to the same NIC.
// The last owner is responsible for deleting the NIC.
//
// +stateify savable
type tunEndpoint struct {
	*channel.Endpoint

	refs.AtomicRefCount

	nicID tcpip.NICID
	name  string
}

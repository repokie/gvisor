// Copyright 2019 The gVisor Authors.
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

package kernfs

import (
	"bytes"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// DynamicSymlink implements kernfs.Inode and represents a symlink pointing
// to a target defined by vfs.DynamicBytesSource.
//
// Must be initialized with Init before first use.
//
// +stateify savable
type DynamicSymlink struct {
	InodeAttrs
	InodeNoopRefCount
	InodeNotDirectory

	target vfs.DynamicBytesSource
}

var _ Inode = (*DynamicSymlink)(nil)

// NewDynamicSymlink creates a new symlink that points to the target returned by
// 'data'.
func NewDynamicSymlink(creds *auth.Credentials, ino uint64, target vfs.DynamicBytesSource) *Dentry {
	link := &DynamicSymlink{target: target}
	link.InodeAttrs.Init(creds, ino, linux.ModeSymlink|0444)
	link.target = target

	d := &Dentry{}
	d.Init(link)
	return d
}

// Readlink implements inodeSymlink.
func (s *DynamicSymlink) Readlink(ctx context.Context) (string, error) {
	buf := bytes.Buffer{}
	if err := s.target.Generate(ctx, &buf); err != nil {
		return "", nil
	}
	return buf.String(), nil
}

// Open implements Inode.
func (s *DynamicSymlink) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	return nil, syserror.ELOOP
}

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

// Package devtmpfs provides an implementation of /dev based on tmpfs,
// analogous to Linux's devtmpfs.
package devtmpfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct {
	initOnce sync.Once
	initErr  error

	// fs is the tmpfs filesystem that backs all mounts of this FilesystemType.
	// root is fs' root. fs and root are immutable.
	fs   *vfs.Filesystem
	root *vfs.Dentry
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fst *FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fst.initOnce.Do(func() {
		fs, root, err := tmpfs.FilesystemType{}.GetFilesystem(ctx, vfsObj, creds, "" /* source */, vfs.GetFilesystemOptions{
			Data: "mode=0755", // opts from drivers/base/devtmpfs.c:devtmpfs_init()
		})
		if err != nil {
			fst.initErr = err
			return
		}
		fst.fs = fs
		fst.root = root
	})
	if fst.initErr != nil {
		return nil, nil, fst.initErr
	}
	fst.fs.IncRef()
	fst.root.IncRef()
	return fst.fs, fst.root, nil
}

// Accessor allows devices to create device special files in devtmpfs.
type Accessor struct {
	vfsObj *vfs.VirtualFilesystem
	mntns  *vfs.MountNamespace
	root   vfs.VirtualDentry
	creds  *auth.Credentials
}

// NewAccessor returns an Accessor that supports creation of device special
// files in the devtmpfs instance registered with name fsTypeName in vfsObj.
func NewAccessor(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, fsTypeName string) (*Accessor, error) {
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "devtmpfs" /* source */, fsTypeName, &vfs.GetFilesystemOptions{})
	if err != nil {
		return nil, err
	}
	return &Accessor{
		vfsObj: vfsObj,
		mntns:  mntns,
		root:   mntns.Root(),
		creds:  creds,
	}, nil
}

// Release must be called when a is no longer in use.
func (a *Accessor) Release() {
	a.root.DecRef()
	a.mntns.DecRef(a.vfsObj)
}

// accessorContext implements context.Context by extending an existing
// context.Context with its own values for VFS-relevant state.
type accessorContext struct {
	context.Context
	a *Accessor
}

// Value implements context.Context.Value.
func (ac *accessorContext) Value(key interface{}) interface{} {
	switch key {
	case vfs.CtxMountNamespace:
		return ac.a.mntns
	case vfs.CtxRoot:
		ac.a.root.IncRef()
		return ac.a.root
	default:
		return ac.Context.Value(key)
	}
}

// CreateFile creates a device special file at the given pathname in the
// devtmpfs instance accessed by a.
func (a *Accessor) CreateFile(ctx context.Context, pathname string, kind vfs.DeviceKind, major, minor uint32, perms uint16) error {
	mode := (linux.FileMode)(perms)
	switch kind {
	case vfs.BlockDevice:
		mode |= linux.S_IFBLK
	case vfs.CharDevice:
		mode |= linux.S_IFCHR
	default:
		panic(fmt.Sprintf("invalid vfs.DeviceKind: %v", kind))
	}
	// NOTE: Linux's devtmpfs refuses to automatically delete files it didn't
	// create, which it recognizes by storing a pointer to the devtmpfsd struct
	// thread in struct inode::i_private. Accessor doesn't yet support deletion
	// of files at all, and probably won't as long as we don't need to support
	// kernel modules, so this is moot for now.
	return a.vfsObj.MknodAt(&accessorContext{
		Context: ctx,
		a:       a,
	}, a.creds, &vfs.PathOperation{
		Root:  a.root,
		Start: a.root,
		Path:  fspath.Parse(pathname),
	}, &vfs.MknodOptions{
		Mode:     mode,
		DevMajor: major,
		DevMinor: minor,
	})
}

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

package memdev

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const zeroDevMinor = 5

// zeroDevice implements vfs.Device for /dev/zero.
type zeroDevice struct{}

// Open implements vfs.Device.Open.
func (zeroDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &zeroFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// zeroFD implements vfs.FileDescriptionImpl for /dev/zero.
type zeroFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *zeroFD) Release() {
	// noop
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *zeroFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return dst.ZeroOut(ctx, dst.NumBytes())
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *zeroFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return dst.ZeroOut(ctx, dst.NumBytes())
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *zeroFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return src.NumBytes(), nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *zeroFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return src.NumBytes(), nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *zeroFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *zeroFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	m, err := mm.NewSharedAnonMappable(opts.Length, pgalloc.MemoryFileProviderFromContext(ctx))
	if err != nil {
		return err
	}
	opts.MappingIdentity = m
	opts.Mappable = m
	return nil
}

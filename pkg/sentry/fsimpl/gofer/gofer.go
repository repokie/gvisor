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

// Package gofer provides a filesystem implementation that is backed by a 9p
// server, interchangably referred to as "gofers" throughout this package.
//
// Lock order:
//   regularFileFD/directoryFD.mu
//     filesystem.renameMu
//       dentry.dirMu
//         filesystem.syncMu
//         dentry.metadataMu
//           *** "memmap.Mappable locks" below this point
//           dentry.mapsMu
//             *** "memmap.Mappable locks taken by Translate" below this point
//             dentry.handleMu
//               dentry.dataMu
//
// Locking dentry.dirMu in multiple dentries requires holding
// filesystem.renameMu for writing.
package gofer

import (
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/unet"
)

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	vfsfs vfs.Filesystem

	// mfp is used to allocate memory that caches regular file contents.
	mfp pgalloc.MemoryFileProvider

	// Immutable options.
	opts filesystemOptions

	// client is the client used by this filesystem.
	client *p9.Client

	// renameMu serves two purposes:
	//
	// - It synchronizes path resolution with renaming initiated by this
	// client.
	//
	// - It is held by path resolution to ensure that reachable dentries remain
	// valid. A dentry is reachable by path resolution if it has a non-zero
	// reference count (such that it is usable as vfs.ResolvingPath.Start() or
	// is reachable from its children), or if it is a child dentry (such that
	// it is reachable from its parent).
	renameMu sync.RWMutex

	// cachedDentries contains all dentries with 0 references. (Due to race
	// conditions, it may also contain dentries with non-zero references.)
	// cachedDentriesLen is the number of dentries in cachedDentries. These
	// fields are protected by renameMu.
	cachedDentries    dentryList
	cachedDentriesLen uint64

	// dentries contains all dentries in this filesystem. specialFileFDs
	// contains all open specialFileFDs. These fields are protected by syncMu.
	syncMu         sync.Mutex
	dentries       map[*dentry]struct{}
	specialFileFDs map[*specialFileFD]struct{}
}

type filesystemOptions struct {
	// "Standard" 9P options.
	fd      int
	aname   string
	interop InteropMode // derived from the "cache" mount option
	msize   uint32
	version string

	// maxCachedDentries is the maximum number of dentries with 0 references
	// retained by the client.
	maxCachedDentries uint64

	// If forcePageCache is true, host FDs may not be used for application
	// memory mappings even if available; instead, the client must perform its
	// own caching of regular file pages. This is primarily useful for testing.
	forcePageCache bool

	// If limitHostFDTranslation is true, apply maxFillRange() constraints to
	// host FD mappings returned by dentry.(memmap.Mappable).Translate(). This
	// makes memory accounting behavior more consistent between cases where
	// host FDs are / are not available, but may increase the frequency of
	// sentry-handled page faults on files for which a host FD is available.
	limitHostFDTranslation bool

	// If overlayfsStaleRead is true, O_RDONLY host FDs provided by the remote
	// filesystem may not be coherent with writable host FDs opened later, so
	// mappings of the former must be replaced by mappings of the latter. This
	// is usually only the case when the remote filesystem is an overlayfs
	// mount on Linux < 4.19.
	overlayfsStaleRead bool

	// If specialRegularFiles is true, application FDs representing regular
	// files will use distinct file handles for each FD, in the same way that
	// application FDs representing "special files" such as sockets do. Note
	// that this disables client caching and mmap for regular files.
	specialRegularFiles bool
}

// InteropMode controls the client's interaction with other remote filesystem
// users.
type InteropMode uint32

const (
	// InteropModeExclusive is appropriate when the filesystem client is the
	// only user of the remote filesystem.
	//
	// - The client may cache arbitrary filesystem state (file data, metadata,
	// filesystem structure, etc.).
	//
	// - Client changes to filesystem state may be sent to the remote
	// filesystem asynchronously, except when server permission checks are
	// necessary.
	//
	// - File timestamps are based on client clocks. This ensures that users of
	// the client observe timestamps that are coherent with their own clocks
	// and consistent with Linux's semantics. However, since it is not always
	// possible for clients to set arbitrary atimes and mtimes, and never
	// possible for clients to set arbitrary ctimes, file timestamp changes are
	// stored in the client only and never sent to the remote filesystem.
	InteropModeExclusive InteropMode = iota

	// InteropModeWritethrough is appropriate when there are read-only users of
	// the remote filesystem that expect to observe changes made by the
	// filesystem client.
	//
	// - The client may cache arbitrary filesystem state.
	//
	// - Client changes to filesystem state must be sent to the remote
	// filesystem synchronously.
	//
	// - File timestamps are based on client clocks. As a corollary, access
	// timestamp changes from other remote filesystem users will not be visible
	// to the client.
	InteropModeWritethrough

	// InteropModeShared is appropriate when there are users of the remote
	// filesystem that may mutate its state other than the client.
	//
	// - The client must verify cached filesystem state before using it.
	//
	// - Client changes to filesystem state must be sent to the remote
	// filesystem synchronously.
	//
	// - File timestamps are based on server clocks. This is necessary to
	// ensure that timestamp changes are synchronized between remote filesystem
	// users.
	//
	// Note that the correctness of InteropModeShared depends on the server
	// correctly implementing 9P fids (i.e. each fid immutably represents a
	// single filesystem object), even in the presence of remote filesystem
	// mutations from other users. If this is violated, the behavior of the
	// client is undefined.
	InteropModeShared
)

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fstype FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: context does not provide a pgalloc.MemoryFileProvider")
		return nil, nil, syserror.EINVAL
	}

	mopts := vfs.GenericParseMountOptions(opts.Data)
	var fsopts filesystemOptions

	// Check that the transport is "fd".
	trans, ok := mopts["trans"]
	if !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: transport must be specified as 'trans=fd'")
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "trans")
	if trans != "fd" {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: unsupported transport: trans=%s", trans)
		return nil, nil, syserror.EINVAL
	}

	// Check that read and write FDs are provided and identical.
	rfdstr, ok := mopts["rfdno"]
	if !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: read FD must be specified as 'rfdno=<file descriptor>")
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "rfdno")
	rfd, err := strconv.Atoi(rfdstr)
	if err != nil {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid read FD: rfdno=%s", rfdstr)
		return nil, nil, syserror.EINVAL
	}
	wfdstr, ok := mopts["wfdno"]
	if !ok {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: write FD must be specified as 'wfdno=<file descriptor>")
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "wfdno")
	wfd, err := strconv.Atoi(wfdstr)
	if err != nil {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid write FD: wfdno=%s", wfdstr)
		return nil, nil, syserror.EINVAL
	}
	if rfd != wfd {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: read FD (%d) and write FD (%d) must be equal", rfd, wfd)
		return nil, nil, syserror.EINVAL
	}
	fsopts.fd = rfd

	// Get the attach name.
	fsopts.aname = "/"
	if aname, ok := mopts["aname"]; ok {
		delete(mopts, "aname")
		fsopts.aname = aname
	}

	// Parse the cache policy. For historical reasons, this defaults to the
	// least generally-applicable option, InteropModeExclusive.
	fsopts.interop = InteropModeExclusive
	if cache, ok := mopts["cache"]; ok {
		delete(mopts, "cache")
		switch cache {
		case "fscache":
			fsopts.interop = InteropModeExclusive
		case "fscache_writethrough":
			fsopts.interop = InteropModeWritethrough
		case "none":
			fsopts.specialRegularFiles = true
			fallthrough
		case "remote_revalidating":
			fsopts.interop = InteropModeShared
		default:
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid cache policy: cache=%s", cache)
			return nil, nil, syserror.EINVAL
		}
	}

	// Parse the 9P message size.
	fsopts.msize = 1024 * 1024 // 1M, tested to give good enough performance up to 64M
	if msizestr, ok := mopts["msize"]; ok {
		delete(mopts, "msize")
		msize, err := strconv.ParseUint(msizestr, 10, 32)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid message size: msize=%s", msizestr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.msize = uint32(msize)
	}

	// Parse the 9P protocol version.
	fsopts.version = p9.HighestVersionString()
	if version, ok := mopts["version"]; ok {
		delete(mopts, "version")
		fsopts.version = version
	}

	// Parse the dentry cache limit.
	fsopts.maxCachedDentries = 1000
	if str, ok := mopts["dentry_cache_limit"]; ok {
		delete(mopts, "dentry_cache_limit")
		maxCachedDentries, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			ctx.Warningf("gofer.FilesystemType.GetFilesystem: invalid dentry cache limit: dentry_cache_limit=%s", str)
			return nil, nil, syserror.EINVAL
		}
		fsopts.maxCachedDentries = maxCachedDentries
	}

	// Handle simple flags.
	if _, ok := mopts["force_page_cache"]; ok {
		delete(mopts, "force_page_cache")
		fsopts.forcePageCache = true
	}
	if _, ok := mopts["limit_host_fd_translation"]; ok {
		delete(mopts, "limit_host_fd_translation")
		fsopts.limitHostFDTranslation = true
	}
	if _, ok := mopts["overlayfs_stale_read"]; ok {
		delete(mopts, "overlayfs_stale_read")
		fsopts.overlayfsStaleRead = true
	}
	// fsopts.specialRegularFiles can only be enabled by specifying
	// "cache=none".

	// Check for unparsed options.
	if len(mopts) != 0 {
		ctx.Warningf("gofer.FilesystemType.GetFilesystem: unknown options: %v", mopts)
		return nil, nil, syserror.EINVAL
	}

	// Establish a connection with the server.
	conn, err := unet.NewSocket(fsopts.fd)
	if err != nil {
		return nil, nil, err
	}

	// Perform version negotiation with the server.
	ctx.UninterruptibleSleepStart(false)
	client, err := p9.NewClient(conn, fsopts.msize, fsopts.version)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	// Ownership of conn has been transferred to client.

	// Perform attach to obtain the filesystem root.
	ctx.UninterruptibleSleepStart(false)
	attachFile, err := client.Attach(fsopts.aname)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	ctx.UninterruptibleSleepStart(false)
	qid, attrMask, attr, err := attachFile.GetAttr(dentryAttrMask())
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		ctx.UninterruptibleSleepStart(false)
		attachFile.Close()
		ctx.UninterruptibleSleepFinish(false)
		client.Close()
		return nil, nil, err
	}

	// Construct the filesystem object.
	fs := &filesystem{
		mfp:            mfp,
		opts:           fsopts,
		client:         client,
		dentries:       make(map[*dentry]struct{}),
		specialFileFDs: make(map[*specialFileFD]struct{}),
	}
	fs.vfsfs.Init(vfsObj, fs)

	// Construct the root dentry.
	root, err := fs.newDentry(ctx, attachFile, qid, attrMask, &attr)
	if err != nil {
		ctx.UninterruptibleSleepStart(false)
		attachFile.Close()
		ctx.UninterruptibleSleepFinish(false)
		fs.Release()
		return nil, nil, err
	}
	// Set the root's reference count to 2. One reference is returned to the
	// caller, and the other is deliberately leaked to prevent the root from
	// being "cached" and subsequently evicted. Its resources will still be
	// cleaned up by fs.Release().
	root.refs = 2

	return &fs.vfsfs, &root.vfsd, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	ctx := context.Background()
	mf := fs.mfp.MemoryFile()

	fs.syncMu.Lock()
	for d := range fs.dentries {
		d.handleMu.Lock()
		d.dataMu.Lock()
		if d.handleWritable {
			// Write dirty cached data to the remote file.
			if err := fsutil.SyncDirtyAll(ctx, &d.cache, &d.dirty, d.size, fs.mfp.MemoryFile(), d.handle.writeFromBlocksAt); err != nil {
				log.Warningf("gofer.filesystem.Release: failed to flush dentry: %v", err)
			}
			// TODO(jamieliu): Do we need to flushf/fsync d?
		}
		// Discard cached pages.
		d.cache.DropAll(mf)
		d.dirty.RemoveAll()
		d.dataMu.Unlock()
		// Close the host fd if one exists.
		if d.handle.fd >= 0 {
			syscall.Close(int(d.handle.fd))
			d.handle.fd = -1
		}
		d.handleMu.Unlock()
	}
	// There can't be any specialFileFDs still using fs, since each such
	// FileDescription would hold a reference on a Mount holding a reference on
	// fs.
	fs.syncMu.Unlock()

	// Close the connection to the server. This implicitly clunks all fids.
	fs.client.Close()
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// Snapshot current dentries and special files.
	fs.syncMu.Lock()
	ds := make([]*dentry, 0, len(fs.dentries))
	for d := range fs.dentries {
		ds = append(ds, d)
	}
	sffds := make([]*specialFileFD, 0, len(fs.specialFileFDs))
	for sffd := range fs.specialFileFDs {
		sffds = append(sffds, sffd)
	}
	fs.syncMu.Unlock()

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error

	// Sync regular files.
	for _, d := range ds {
		if !d.TryIncRef() {
			continue
		}
		err := d.syncSharedHandle(ctx)
		d.DecRef()
		if err != nil && retErr == nil {
			retErr = err
		}
	}

	// Sync special files, which may be writable but do not use dentry shared
	// handles (so they won't be synced by the above).
	for _, sffd := range sffds {
		if !sffd.vfsfd.TryIncRef() {
			continue
		}
		err := sffd.Sync(ctx)
		sffd.vfsfd.DecRef()
		if err != nil && retErr == nil {
			retErr = err
		}
	}

	return retErr
}

// dentry implements vfs.DentryImpl.
type dentry struct {
	vfsd vfs.Dentry

	// refs is the reference count. Each dentry holds a reference on its
	// parent, even if disowned. refs is accessed using atomic memory
	// operations.
	refs int64

	// fs is the owning filesystem. fs is immutable.
	fs *filesystem

	// We don't support hard links, so each dentry maps 1:1 to an inode.

	// file is the unopened p9.File that backs this dentry. file is immutable.
	file p9.File

	// If cached is true, dentryEntry links dentry into
	// filesystem.cachedDentries. cached and dentryEntry are protected by
	// filesystem.renameMu.
	cached bool
	dentryEntry

	dirMu sync.Mutex

	// If this dentry represents a directory, and InteropModeShared is not in
	// effect, negativeChildren is a set of child names in this directory that
	// are known not to exist. negativeChildren is protected by dirMu.
	negativeChildren map[string]struct{}

	// If this dentry represents a directory, InteropModeShared is not in
	// effect, and dirents is not nil, it is a cache of all entries in the
	// directory, in the order they were returned by the server. dirents is
	// protected by dirMu.
	dirents []vfs.Dirent

	// Cached metadata; protected by metadataMu and accessed using atomic
	// memory operations unless otherwise specified.
	metadataMu sync.Mutex
	ino        uint64 // immutable
	mode       uint32 // type is immutable, perms are mutable
	uid        uint32 // auth.KUID, but stored as raw uint32 for sync/atomic
	gid        uint32 // auth.KGID, but ...
	blockSize  uint32 // 0 if unknown
	// Timestamps, all nsecs from the Unix epoch.
	atime int64
	mtime int64
	ctime int64
	btime int64
	// File size, protected by dataMu instead of metadataMu.
	size uint64

	mapsMu sync.Mutex

	// If this dentry represents a regular file, mappings tracks mappings of
	// the file into memmap.MappingSpaces. mappings is protected by mapsMu.
	mappings memmap.MappingSet

	// If this dentry represents a regular file or directory:
	//
	// - handle is the I/O handle used by all regularFileFDs/directoryFDs
	// representing this dentry.
	//
	// - handleReadable is true if handle is readable.
	//
	// - handleWritable is true if handle is writable.
	//
	// Invariants:
	//
	// - If handleReadable == handleWritable == false, then handle.file == nil
	// (i.e. there is no open handle). Conversely, if handleReadable ||
	// handleWritable == true, then handle.file != nil (i.e. there is an open
	// handle).
	//
	// - handleReadable and handleWritable cannot transition from true to false
	// (i.e. handles may not be downgraded).
	//
	// These fields are protected by handleMu.
	handleMu       sync.RWMutex
	handle         handle
	handleReadable bool
	handleWritable bool

	dataMu sync.RWMutex

	// If this dentry represents a regular file that is client-cached, cache
	// maps offsets into the cached file to offsets into
	// filesystem.mfp.MemoryFile() that store the file's data. cache is
	// protected by dataMu.
	cache fsutil.FileRangeSet

	// If this dentry represents a regular file that is client-cached, dirty
	// tracks dirty segments in cache. dirty is protected by dataMu.
	dirty fsutil.DirtySet

	// pf implements platform.File for mappings of handle.fd.
	pf dentryPlatformFile

	// If this dentry represents a symbolic link, InteropModeShared is not in
	// effect, and haveTarget is true, target is the symlink target. haveTarget
	// and target are protected by dataMu.
	haveTarget bool
	target     string
}

// dentryAttrMask returns a p9.AttrMask enabling all attributes used by the
// gofer client.
func dentryAttrMask() p9.AttrMask {
	return p9.AttrMask{
		Mode:  true,
		UID:   true,
		GID:   true,
		ATime: true,
		MTime: true,
		CTime: true,
		Size:  true,
		BTime: true,
	}
}

// newDentry creates a new dentry representing the given file. The dentry
// initially has no references, but is not cached; it is the caller's
// responsibility to set the dentry's reference count and/or call
// dentry.checkCachingLocked() as appropriate.
func (fs *filesystem) newDentry(ctx context.Context, file p9.File, qid p9.QID, mask p9.AttrMask, attr *p9.Attr) (*dentry, error) {
	if !mask.Mode {
		ctx.Warningf("can't create gofer.dentry without file type")
		return nil, syserror.EIO
	}
	if attr.Mode.FileType() == p9.ModeRegular && !mask.Size {
		ctx.Warningf("can't create regular file gofer.dentry without file size")
		return nil, syserror.EIO
	}

	d := &dentry{
		fs:        fs,
		file:      file,
		ino:       qid.Path,
		mode:      uint32(attr.Mode),
		uid:       auth.NoID,
		gid:       auth.NoID,
		blockSize: uint32(attr.BlockSize),
		handle: handle{
			fd: -1,
		},
	}
	d.pf.dentry = d
	if mask.UID && attr.UID.Ok() {
		d.uid = uint32(attr.UID)
	}
	if mask.GID && attr.GID.Ok() {
		d.gid = uint32(attr.GID)
	}
	if mask.Size {
		d.size = attr.Size
	}
	if mask.ATime {
		d.atime = dentryTimestampFromP9(attr.ATimeSeconds, attr.ATimeNanoSeconds)
	}
	if mask.MTime {
		d.mtime = dentryTimestampFromP9(attr.MTimeSeconds, attr.MTimeNanoSeconds)
	}
	if mask.CTime {
		d.ctime = dentryTimestampFromP9(attr.CTimeSeconds, attr.CTimeNanoSeconds)
	}
	if mask.BTime {
		d.btime = dentryTimestampFromP9(attr.BTimeSeconds, attr.BTimeNanoSeconds)
	}
	d.vfsd.Init(d)

	fs.syncMu.Lock()
	fs.dentries[d] = struct{}{}
	fs.syncMu.Unlock()
	return d, nil
}

// updateFromP9Attrs is called to update d's metadata after an update from the
// remote filesystem.
func (d *dentry) updateFromP9Attrs(mask p9.AttrMask, attr *p9.Attr) {
	d.metadataMu.Lock()
	if mask.Mode {
		if got, want := uint32(attr.Mode.FileType()), d.mode&linux.S_IFMT; got != want {
			d.metadataMu.Unlock()
			panic(fmt.Sprintf("gofer.dentry file type changed from %O to %O", want, got))
		}
		atomic.StoreUint32(&d.mode, uint32(attr.Mode))
	}
	if mask.UID {
		if attr.UID.Ok() {
			atomic.StoreUint32(&d.uid, uint32(attr.UID))
		} else {
			atomic.StoreUint32(&d.uid, auth.NoID)
		}
	}
	if mask.GID {
		if attr.GID.Ok() {
			atomic.StoreUint32(&d.gid, uint32(attr.GID))
		} else {
			atomic.StoreUint32(&d.gid, auth.NoID)
		}
	}
	// There is no P9_GETATTR_* bit for I/O block size.
	if attr.BlockSize != 0 {
		atomic.StoreUint32(&d.blockSize, uint32(attr.BlockSize))
	}
	if mask.ATime {
		atomic.StoreInt64(&d.atime, dentryTimestampFromP9(attr.ATimeSeconds, attr.ATimeNanoSeconds))
	}
	if mask.MTime {
		atomic.StoreInt64(&d.mtime, dentryTimestampFromP9(attr.MTimeSeconds, attr.MTimeNanoSeconds))
	}
	if mask.CTime {
		atomic.StoreInt64(&d.ctime, dentryTimestampFromP9(attr.CTimeSeconds, attr.CTimeNanoSeconds))
	}
	if mask.BTime {
		atomic.StoreInt64(&d.btime, dentryTimestampFromP9(attr.BTimeSeconds, attr.BTimeNanoSeconds))
	}
	d.metadataMu.Unlock()
	if mask.Size {
		d.dataMu.Lock()
		atomic.StoreUint64(&d.size, attr.Size)
		d.dataMu.Unlock()
	}
}

func (d *dentry) updateFromGetattr(ctx context.Context) error {
	// Use d.handle.file, which represents a 9P fid that has been opened, in
	// preference to d.file, which represents a 9P fid that has not. This may
	// be significantly more efficient in some implementations.
	var (
		file            p9.File
		handleMuRLocked bool
	)
	d.handleMu.RLock()
	if d.handle.file != nil {
		file = d.handle.file
		handleMuRLocked = true
	} else {
		file = d.file
		d.handleMu.RUnlock()
	}
	ctx.UninterruptibleSleepStart(false)
	_, attrMask, attr, err := file.GetAttr(dentryAttrMask())
	ctx.UninterruptibleSleepFinish(false)
	if handleMuRLocked {
		d.handleMu.RUnlock()
	}
	if err != nil {
		return err
	}
	d.updateFromP9Attrs(attrMask, &attr)
	return nil
}

func (d *dentry) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_NLINK | linux.STATX_UID | linux.STATX_GID | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME | linux.STATX_INO | linux.STATX_SIZE | linux.STATX_BTIME
	stat.Blksize = atomic.LoadUint32(&d.blockSize)
	stat.Nlink = 1
	if d.isDir() {
		stat.Nlink = 2
	}
	stat.UID = atomic.LoadUint32(&d.uid)
	stat.GID = atomic.LoadUint32(&d.gid)
	stat.Mode = uint16(atomic.LoadUint32(&d.mode))
	stat.Ino = d.ino
	stat.Size = atomic.LoadUint64(&d.size)
	stat.Atime = statxTimestampFromDentry(atomic.LoadInt64(&d.atime))
	stat.Btime = statxTimestampFromDentry(atomic.LoadInt64(&d.btime))
	stat.Ctime = statxTimestampFromDentry(atomic.LoadInt64(&d.ctime))
	stat.Mtime = statxTimestampFromDentry(atomic.LoadInt64(&d.mtime))
	// TODO(jamieliu): device number
}

func (d *dentry) checkPermissions(creds *auth.Credentials, ats vfs.AccessTypes, isDir bool) error {
	return vfs.GenericCheckPermissions(creds, ats, isDir, uint16(atomic.LoadUint32(&d.mode))&0777, auth.KUID(atomic.LoadUint32(&d.uid)), auth.KGID(atomic.LoadUint32(&d.gid)))
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef() {
	if atomic.AddInt64(&d.refs, 1) <= 1 {
		panic("gofer.dentry.IncRef() called without holding a reference")
	}
}

// Preconditions: d.fs.renameMu must be locked. Either d has a non-zero
// reference count, or it is a child dentry.
func (d *dentry) incRefLocked() {
	// By precondition, we can increment d's reference count even if it's 0
	// (d.checkCachingLocked() can't have destroyed it). We can't remove d from
	// filesystem.cachedDentries, since we may not hold fs.renameMu for
	// writing; instead, they are lazily removed from filesystem.cachedDentries
	// by cache eviction.
	atomic.AddInt64(&d.refs, 1)
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef() bool {
	for {
		refs := atomic.LoadInt64(&d.refs)
		if refs == 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&d.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef() {
	if refs := atomic.AddInt64(&d.refs, -1); refs == 0 {
		d.fs.renameMu.Lock()
		d.checkCachingLocked()
		d.fs.renameMu.Unlock()
	} else if refs < 0 {
		panic("gofer.dentry.DecRef() called without holding a reference")
	}
}

// checkCachingLocked should be called after d's reference count becomes 0 or it
// becomes disowned.
//
// Preconditions: d.fs.renameMu must be locked for writing.
func (d *dentry) checkCachingLocked() {
	// Dentries with a non-zero reference count must be retained. (The only way
	// to obtain a reference on a dentry with zero references is via path
	// resolution, which requires renameMu, so if d.refs is zero then it will
	// remain zero while we hold renameMu for writing.)
	if atomic.LoadInt64(&d.refs) != 0 {
		if d.cached {
			d.fs.cachedDentries.Remove(d)
			d.fs.cachedDentriesLen--
			d.cached = false
		}
		return
	}
	// Non-child dentries with zero references are no longer reachable by path
	// resolution and should be dropped immediately.
	if d.vfsd.Parent() == nil || d.vfsd.IsDisowned() {
		if d.cached {
			d.fs.cachedDentries.Remove(d)
			d.fs.cachedDentriesLen--
			d.cached = false
		}
		d.destroyLocked()
		return
	}
	// If d is already cached, just move it to the front of the LRU.
	if d.cached {
		d.fs.cachedDentries.Remove(d)
		d.fs.cachedDentries.PushFront(d)
		return
	}
	// Cache the dentry, then evict the least recently used cached dentry if
	// the cache becomes over-full.
	d.fs.cachedDentries.PushFront(d)
	d.fs.cachedDentriesLen++
	d.cached = true
	if d.fs.cachedDentriesLen > d.fs.opts.maxCachedDentries {
		victim := d.fs.cachedDentries.Back()
		d.fs.cachedDentries.Remove(victim)
		d.fs.cachedDentriesLen--
		victim.cached = false
		// victim.refs may have become non-zero from an earlier path
		// resolution since it was inserted into fs.cachedDentries; see
		// dentry.incRefLocked(). Either way, we brought
		// fs.cachedDentriesLen back down to fs.opts.maxCachedDentries, so
		// we don't loop.
		if atomic.LoadInt64(&victim.refs) == 0 {
			if victimParentVFSD := victim.vfsd.Parent(); victimParentVFSD != nil {
				victimParent := victimParentVFSD.Impl().(*dentry)
				victimParent.dirMu.Lock()
				if !victim.vfsd.IsDisowned() {
					// victim can't be a mount point (in any mount
					// namespace), since VFS holds references on mount
					// points.
					d.fs.vfsfs.VirtualFilesystem().ForceDeleteDentry(&victim.vfsd)
					// We're only deleting the dentry, not the file it
					// represents, so we don't need to update
					// victimParent.dirents etc.
				}
				victimParent.dirMu.Unlock()
			}
			victim.destroyLocked()
		}
	}
}

// Preconditions: d.fs.renameMu must be locked for writing. d.refs == 0. d is
// not a child dentry.
func (d *dentry) destroyLocked() {
	d.handleMu.Lock()
	if d.handle.file != nil {
		mf := d.fs.mfp.MemoryFile()
		d.dataMu.Lock()
		// Write dirty pages back to the remote filesystem.
		if d.handleWritable {
			if err := fsutil.SyncDirtyAll(context.Background(), &d.cache, &d.dirty, d.size, mf, d.handle.writeFromBlocksAt); err != nil {
				log.Warningf("gofer.dentry.DecRef: failed to write dirty data back: %v", err)
			}
			d.dataMu.Unlock()
		}
		// Discard cached data.
		d.cache.DropAll(mf)
		d.dirty.RemoveAll()
		d.dataMu.Unlock()
		// Clunk open fids and close open host FDs.
		d.handle.close()
	}
	d.handleMu.Unlock()
	d.file.Close()
	// Remove d from the set of all dentries.
	d.fs.syncMu.Lock()
	delete(d.fs.dentries, d)
	d.fs.syncMu.Unlock()
	// Drop the reference held by d on its parent.
	if parentVFSD := d.vfsd.Parent(); parentVFSD != nil {
		parent := parentVFSD.Impl().(*dentry)
		// This is parent.DecRef() without recursive locking of d.fs.renameMu.
		if refs := atomic.AddInt64(&parent.refs, -1); refs == 0 {
			parent.checkCachingLocked()
		} else if refs < 0 {
			panic("gofer.dentry.DecRef() called without holding a reference")
		}
	}
}

// Preconditions: d.isRegularFile() || d.isDirectory().
func (d *dentry) ensureSharedHandle(ctx context.Context, read, write, trunc bool) error {
	// O_TRUNC unconditionally requires us to obtain a new handle (opened with
	// O_TRUNC).
	if !trunc {
		d.handleMu.RLock()
		if (!read || d.handleReadable) && (!write || d.handleWritable) {
			// The current handle is sufficient.
			d.handleMu.RUnlock()
			return nil
		}
		d.handleMu.RUnlock()
	}

	haveOldFD := false
	d.handleMu.Lock()
	if (read && !d.handleReadable) || (write && !d.handleWritable) || trunc {
		// Get a new handle.
		wantReadable := d.handleReadable || read
		wantWritable := d.handleWritable || write
		h, err := openHandle(ctx, d.file, wantReadable, wantWritable, trunc)
		if err != nil {
			d.handleMu.Unlock()
			return err
		}
		if d.handle.file != nil {
			// Check that old and new handles are compatible: If the old handle
			// includes a host file descriptor but the new one does not, or
			// vice versa, old and new memory mappings may be incoherent.
			haveOldFD = d.handle.fd >= 0
			haveNewFD := h.fd >= 0
			if haveOldFD != haveNewFD {
				d.handleMu.Unlock()
				ctx.Warningf("gofer.dentry.ensureSharedHandle: can't change host FD availability from %v to %v across dentry handle upgrade", haveOldFD, haveNewFD)
				ctx.UninterruptibleSleepStart(false)
				h.close()
				ctx.UninterruptibleSleepFinish(false)
				return syserror.EIO
			}
			if haveOldFD {
				// We may have raced with callers of d.pf.FD() that are now
				// using the old FD, preventing us from safely closing it. We
				// could handle this by invalidating existing
				// memmap.Translations (which are required to use d.pf), but
				// this is expensive. Instead, use dup2() to make the old file
				// descriptor refer to the new file description, then close the
				// new file descriptor (which is no longer needed). Racing
				// callers may use the old or new file description, but this
				// doesn't matter since they refer to the same file (unless
				// d.fs.opts.overlayfsStaleRead is true, which we handle
				// separately).
				if err := syscall.Dup2(int(h.fd), int(d.handle.fd)); err != nil {
					d.handleMu.Unlock()
					ctx.Warningf("gofer.dentry.ensureSharedHandle: failed to dup fd %d to fd %d: %v", h.fd, d.handle.fd, err)
					ctx.UninterruptibleSleepStart(false)
					h.close()
					ctx.UninterruptibleSleepFinish(false)
					return err
				}
				ctx.UninterruptibleSleepStart(false)
				syscall.Close(int(h.fd))
				ctx.UninterruptibleSleepFinish(false)
				h.fd = d.handle.fd
				if d.fs.opts.overlayfsStaleRead {
					// Replace sentry mappings of the old FD with mappings of
					// the new FD, since the two are not necessarily coherent.
					if err := d.pf.hostFileMapper.RegenerateMappings(int(h.fd)); err != nil {
						d.handleMu.Unlock()
						ctx.Warningf("gofer.dentry.ensureSharedHandle: failed to replace sentry mappings of old FD with mappings of new FD: %v", err)
						ctx.UninterruptibleSleepStart(false)
						h.close()
						ctx.UninterruptibleSleepFinish(false)
						return err
					}
				}
				// Clunk the old fid before making the new handle visible (by
				// unlocking d.handleMu).
				ctx.UninterruptibleSleepStart(false)
				d.handle.file.Close()
				ctx.UninterruptibleSleepFinish(false)
			}
		}
		// Switch to the new handle.
		d.handle = h
		d.handleReadable = wantReadable
		d.handleWritable = wantWritable
	}
	d.handleMu.Unlock()

	if d.fs.opts.overlayfsStaleRead && haveOldFD {
		// Invalidate application mappings that may be using the old FD; they
		// will be replaced with mappings using the new FD after future calls
		// to d.Translate(). This requires holding d.mapsMu, which precedes
		// d.handleMu in the lock order.
		d.mapsMu.Lock()
		d.mappings.InvalidateAll(memmap.InvalidateOpts{})
		d.mapsMu.Unlock()
	}

	return nil
}

// fileDescription is embedded by gofer implementations of
// vfs.FileDescriptionImpl.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

	flags uint32 // status flags; immutable
}

func (fd *fileDescription) filesystem() *filesystem {
	return fd.vfsfd.Mount().Filesystem().Impl().(*filesystem)
}

func (fd *fileDescription) dentry() *dentry {
	return fd.vfsfd.Dentry().Impl().(*dentry)
}

// StatusFlags implements vfs.FileDescriptionImpl.StatusFlags.
func (fd *fileDescription) StatusFlags(ctx context.Context) (uint32, error) {
	return fd.flags, nil
}

// SetStatusFlags implements vfs.FileDescriptionImpl.SetStatusFlags.
func (fd *fileDescription) SetStatusFlags(ctx context.Context, flags uint32) error {
	// None of the flags settable by fcntl(F_SETFL) are supported yet, so this
	// is a no-op.
	return nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	d := fd.dentry()
	if d.fs.opts.interop == InteropModeShared {
		// TODO(jamieliu): Use specialFileFD.handle.file for the getattr if
		// available?
		if err := d.updateFromGetattr(ctx); err != nil {
			return linux.Statx{}, err
		}
	}
	var stat linux.Statx
	d.statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
	// FIXME(jamieliu): implement
	return syserror.EPERM
}

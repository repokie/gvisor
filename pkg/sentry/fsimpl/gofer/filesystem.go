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

package gofer

import (
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// maxFilenameLen is the maximum length of a filename. This is dictated by 9P's
// encoding of strings, which uses 2 bytes for the length prefix.
const maxFilenameLen = (1 << 16) - 1

// A dentryBuffer is a mutable []*dentry. This type exists because Go lacks
// generics, so sync.Pool operates on interface{}, so each call to (what should
// be) sync.Pool<[]*dentry>.Put() causes the runtime to heap-allocate a slice
// header.
type dentryBuffer struct {
	val []*dentry
}

func (db *dentryBuffer) push(d *dentry) {
	db.val = append(db.val, d)
}

var dentryBufferPool = sync.Pool{
	New: func() interface{} {
		return &dentryBuffer{
			val: make([]*dentry, 0, 4), // arbitrary non-zero initial capacity
		}
	},
}

func getDentryBuffer() *dentryBuffer {
	return dentryBufferPool.Get().(*dentryBuffer)
}

func putDentryBuffer(db *dentryBuffer) {
	if db == nil {
		return
	}
	for i := range db.val {
		db.val[i] = nil
	}
	db.val = db.val[:0]
	dentryBufferPool.Put(db)
}

// stepExistingLocked resolves rp.Component() to a dentry representing an
// existing file in parent directory d. Dentries which may become cached as a
// result of the traversal are appended to *db; if *db is nil, a dentryBuffer
// will be created.
//
// Preconditions: fs.renameMu must be locked. d.dirMu must be locked.
// !rp.Done(). If fs.opts.interop == InteropModeShared, then d's cached
// metadata must be up to date.
func (fs *filesystem) stepExistingLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry, db **dentryBuffer) (*dentry, error) {
	if !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	if err := d.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
		return nil, err
	}
afterSymlink:
	nextName := rp.Component()
	if len(nextName) > maxFilenameLen {
		return nil, syserror.ENAMETOOLONG
	}
	nextVFSD, err := rp.ResolveComponent(&d.vfsd)
	if err != nil {
		return nil, err
	}
	if nextVFSD == nil || (fs.opts.interop == InteropModeShared && nextName != "." && nextName != "..") {
		// Check if we've already cached this lookup with a negative result.
		if d.negativeChildren != nil {
			if _, ok := d.negativeChildren[nextName]; ok {
				return nil, syserror.ENOENT
			}
		}
		// Perform the remote lookup.
		ctx.UninterruptibleSleepStart(false)
		qids, file, attrMask, attr, err := d.file.WalkGetAttr([]string{nextName})
		ctx.UninterruptibleSleepFinish(false)
		// To simplify later logic, ensure that the only possibilities are:
		// - err == nil    <=> file != nil <=> len(qids) == 1
		// - err == ENOENT <=> file == nil <=> len(qids) == 0
		switch err {
		case nil:
			if file == nil {
				ctx.Warningf("gofer.filesystem.stepExistingLocked: p9.File.WalkGetAttr returned no File with no error")
				return nil, syserror.EIO
			}
			if len(qids) != 1 {
				ctx.Warningf("gofer.filesystem.stepExistingLocked: p9.File.WalkGetAttr returned %d qids (%v), wanted 1", len(qids), qids)
				file.Close()
				return nil, syserror.EIO
			}
		case syserror.ENOENT:
			// These conditions are nonsensical, but not fatal, so we don't
			// return EIO.
			if file != nil {
				ctx.Warningf("gofer.filesystem.stepExistingLocked: p9.File.WalkGetAttr returned a non-nil File with ENOENT")
				ctx.UninterruptibleSleepStart(false)
				file.Close()
				ctx.UninterruptibleSleepFinish(false)
				file = nil
			}
			if len(qids) != 0 {
				ctx.Warningf("gofer.filesystem.stepExistingLocked: p9.File.WalkGetAttr returned %d qids (%v) with ENOENT")
				qids = nil
			}
		default:
			return nil, err
		}
		if nextVFSD == nil || len(qids) == 0 || qids[0].Path != nextVFSD.Impl().(*dentry).ino {
			// Either we had no information about the file at this path, or we
			// did but the file has changed.
			if nextVFSD != nil {
				// Remove the stale dentry from the tree.
				rp.VirtualFilesystem().ForceDeleteDentry(nextVFSD)
				if *db == nil {
					*db = getDentryBuffer()
				}
				(*db).push(nextVFSD.Impl().(*dentry))
			}
			if len(qids) == 0 {
				if fs.opts.interop != InteropModeShared {
					// Cache this negative lookup.
					if d.negativeChildren == nil {
						d.negativeChildren = make(map[string]struct{})
					}
					d.negativeChildren[nextName] = struct{}{}
				}
				return nil, syserror.ENOENT
			}
			// Create the new dentry.
			next, err := fs.newDentry(ctx, file, qids[0], attrMask, &attr)
			if err != nil {
				ctx.UninterruptibleSleepStart(false)
				file.Close()
				ctx.UninterruptibleSleepFinish(false)
				return nil, err
			}
			nextVFSD = &next.vfsd
			d.incRefLocked() // reference held by next on its parent d
			d.vfsd.InsertChild(nextVFSD, nextName)
			// For now, next has 0 references, so our caller should call
			// next.checkCachingLocked().
			if *db == nil {
				*db = getDentryBuffer()
			}
			(*db).push(next)
		} else {
			// The file at this path hasn't changed. Just update cached
			// metadata.
			ctx.UninterruptibleSleepStart(false)
			file.Close()
			ctx.UninterruptibleSleepFinish(false)
			nextVFSD.Impl().(*dentry).updateFromP9Attrs(attrMask, &attr)
		}
	} else if fs.opts.interop == InteropModeShared && nextName == ".." {
		// We must assume nextVFSD is correct, because if d has been moved
		// elsewhere in the remote filesystem so that its parent has changed,
		// we have no way of determining its new parent's location in the
		// filesystem. Get updated metadata for nextVFSD.
		next := nextVFSD.Impl().(*dentry)
		ctx.UninterruptibleSleepStart(false)
		_, attrMask, attr, err := next.file.GetAttr(dentryAttrMask())
		ctx.UninterruptibleSleepFinish(false)
		if err != nil {
			return nil, err
		}
		next.updateFromP9Attrs(attrMask, &attr)
	}
	next := nextVFSD.Impl().(*dentry)
	if next.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := next.readlink(ctx, fs, rp.Mount())
		if err != nil {
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, err
		}
		goto afterSymlink // don't check the current directory again
	}
	rp.Advance()
	return next, nil
}

// walkExistingLocked resolves rp to a dentry representing an existing file.
//
// Preconditions: fs.renameMu must be locked.
func (fs *filesystem) walkExistingLocked(ctx context.Context, rp *vfs.ResolvingPath, db **dentryBuffer) (*dentry, error) {
	d := rp.Start().Impl().(*dentry)
	if fs.opts.interop == InteropModeShared {
		// Get updated metadata for rp.Start() as required by fs.stepExistingLocked().
		if err := d.updateFromGetattr(ctx); err != nil {
			return nil, err
		}
	}
	for !rp.Done() {
		d.dirMu.Lock()
		next, err := fs.stepExistingLocked(ctx, rp, d, db)
		d.dirMu.Unlock()
		if err != nil {
			return nil, err
		}
		d = next
	}
	if rp.MustBeDir() && !d.isDir() {
		return nil, syserror.ENOTDIR
	}
	return d, nil
}

// renameMuRUnlockAndRelease calls fs.renameMu.RUnlock(), then calls
// dentry.checkCachingLocked on all dentries in db with fs.renameMu locked for
// writing.
//
// db is a pointer-to-pointer since defer evaluates its arguments immediately,
// but dentryBuffers are allocated lazily, and it's much easier to say "defer
// fs.renameMuRUnlockAndRelease(&db)" than "defer func() {
// fs.renameMuRUnlockAndRelease(db) }()" to work around this.
func (fs *filesystem) renameMuRUnlockAndRelease(db **dentryBuffer) {
	fs.renameMu.RUnlock()
	if *db == nil {
		return
	}
	if len((*db).val) != 0 {
		fs.renameMu.Lock()
		for _, d := range (*db).val {
			d.checkCachingLocked()
		}
		fs.renameMu.Unlock()
	}
	putDentryBuffer(*db)
}

func (fs *filesystem) renameMuUnlockAndRelease(db **dentryBuffer) {
	if *db != nil && len((*db).val) != 0 {
		for _, d := range (*db).val {
			d.checkCachingLocked()
		}
	}
	fs.renameMu.Unlock()
	putDentryBuffer(*db)
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	var db *dentryBuffer
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndRelease(&db)
	d, err := fs.walkExistingLocked(ctx, rp, &db)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.isDir() {
			return nil, syserror.ENOTDIR
		}
		if err := d.checkPermissions(rp.Credentials(), vfs.MayExec, true); err != nil {
			return nil, err
		}
	}
	d.incRefLocked()
	return &d.vfsd, nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Filter out flags that are not supported by memfs. O_DIRECTORY and
	// O_NOFOLLOW have no effect here (they're handled by VFS by setting
	// appropriate bits in rp), but are returned by
	// FileDescriptionImpl.StatusFlags().
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC | linux.O_DIRECTORY | linux.O_NOFOLLOW

	var db *dentryBuffer
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndRelease(&db)

	if opts.Flags&linux.O_CREAT == 0 {
		d, err := fs.walkExistingLocked(ctx, rp, &db)
		if err != nil {
			return nil, err
		}
		return d.openLocked(ctx, rp, opts.Flags)
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	d := rp.Start().Impl().(*dentry)
	if fs.opts.interop == InteropModeShared {
		// Get updated metadata for d as required by fs.stepExistingLocked().
		if err := d.updateFromGetattr(ctx); err != nil {
			return nil, err
		}
	}
	if rp.Done() {
		// Reject attempts to open directories with O_CREAT.
		if rp.MustBeDir() {
			return nil, syserror.EISDIR
		}
		if mustCreate {
			return nil, syserror.EEXIST
		}
		return d.openLocked(ctx, rp, opts.Flags)
	}

afterTrailingSymlink:
	// Walk to the parent directory of the last path component.
	for !rp.Final() {
		d.dirMu.Lock()
		next, err := fs.stepExistingLocked(ctx, rp, d, &db)
		d.dirMu.Unlock()
		if err != nil {
			return nil, err
		}
		d = next
	}
	// Reject attempts to open directories with O_CREAT.
	if rp.MustBeDir() {
		return nil, syserror.EISDIR
	}
	if pc := rp.Component(); pc == "." || pc == ".." {
		return nil, syserror.EISDIR
	}

	// Determine whether or not we need to create a file.
	d.dirMu.Lock()
	child, err := fs.stepExistingLocked(ctx, rp, d, &db)
	if err != nil {
		if err == syserror.ENOENT {
			fd, err := d.createAndOpenChildLocked(ctx, rp, &opts)
			d.dirMu.Unlock()
			return fd, err
		}
		d.dirMu.Unlock()
		return nil, err
	}
	d.dirMu.Unlock()

	// Open existing file or follow symlink.
	if mustCreate {
		return nil, syserror.EEXIST
	}
	if child.isSymlink() && rp.ShouldFollowSymlink() {
		target, err := child.readlink(ctx, fs, rp.Mount())
		if err != nil {
			return nil, err
		}
		if err := rp.HandleSymlink(target); err != nil {
			return nil, err
		}
		goto afterTrailingSymlink
	}
	return child.openLocked(ctx, rp, opts.Flags)
}

// Preconditions: fs.renameMu must be locked.
func (d *dentry) openLocked(ctx context.Context, rp *vfs.ResolvingPath, flags uint32) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(flags)
	if err := d.checkPermissions(rp.Credentials(), ats, d.isDir()); err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	filetype := atomic.LoadUint32(&d.mode) & linux.S_IFMT
	switch {
	case filetype == linux.S_IFREG && !d.fs.opts.specialRegularFiles:
		fd := &regularFileFD{
			fileDescription: fileDescription{
				flags: flags,
			},
			readable: vfs.MayReadFileWithOpenFlags(flags),
			writable: vfs.MayWriteFileWithOpenFlags(flags),
		}
		if fd.writable {
			if err := mnt.CheckBeginWrite(); err != nil {
				return nil, err
			}
		}
		if err := d.ensureSharedHandle(ctx, ats&vfs.MayRead != 0, ats&vfs.MayWrite != 0, flags&linux.O_TRUNC != 0); err != nil {
			if fd.writable {
				mnt.EndWrite()
			}
			return nil, err
		}
		mnt.IncRef()
		d.incRefLocked()
		fd.vfsfd.Init(fd, mnt, &d.vfsd)
		// mnt.EndWrite() is called by regularFileFD.Release().
		return &fd.vfsfd, nil
	case filetype == linux.S_IFDIR:
		// Can't open directories writably.
		if ats&vfs.MayWrite != 0 {
			return nil, syserror.EISDIR
		}
		if err := d.ensureSharedHandle(ctx, ats&vfs.MayRead != 0, false /* write */, false /* trunc */); err != nil {
			return nil, err
		}
		fd := &directoryFD{
			fileDescription: fileDescription{
				flags: flags,
			},
		}
		mnt.IncRef()
		d.incRefLocked()
		fd.vfsfd.Init(fd, mnt, &d.vfsd)
		return &fd.vfsfd, nil
	case filetype == linux.S_IFLNK:
		// Can't open symlinks without O_PATH (which is unimplemented).
		return nil, syserror.ELOOP
	default:
		fd := &specialFileFD{
			fileDescription: fileDescription{
				flags: flags,
			},
			readable: vfs.MayReadFileWithOpenFlags(flags),
			writable: vfs.MayWriteFileWithOpenFlags(flags),
		}
		if fd.writable {
			if err := mnt.CheckBeginWrite(); err != nil {
				return nil, err
			}
		}
		// Get a handle for this FD.
		h, err := openHandle(ctx, d.file, ats&vfs.MayRead != 0, ats&vfs.MayWrite != 0, flags&linux.O_TRUNC != 0)
		if err != nil {
			if fd.writable {
				rp.Mount().EndWrite()
			}
			return nil, err
		}
		fd.handle = h
		mnt.IncRef()
		d.incRefLocked()
		fd.vfsfd.Init(fd, mnt, &d.vfsd)
		// mnt.EndWrite() is called by specialFileFD.Release().
		return &fd.vfsfd, nil
	}
}

// Preconditions: fs.renameMu must be locked. d.dirMu must be locked.
func (d *dentry) createAndOpenChildLocked(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Check that the parent directory is writable.
	if err := d.checkPermissions(rp.Credentials(), vfs.MayWrite, true); err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, err
	}
	// Can't defer mnt.EndWrite(); see below.

	// 9P2000.L's lcreate takes a fid representing the parent directory, and
	// converts it into an open fid representing the created file, so we need
	// to duplicate the directory fid first.
	ctx.UninterruptibleSleepStart(false)
	_, dirfile, err := d.file.Walk(nil)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		mnt.EndWrite()
		return nil, err
	}
	creds := rp.Credentials()
	childName := rp.Component()
	ctx.UninterruptibleSleepStart(false)
	fdobj, openFile, createQID, _, err := dirfile.Create(childName, (p9.OpenFlags)(opts.Flags), (p9.FileMode)(opts.Mode), (p9.UID)(creds.EffectiveKUID), (p9.GID)(creds.EffectiveKGID))
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		mnt.EndWrite()
		ctx.UninterruptibleSleepStart(false)
		dirfile.Close()
		ctx.UninterruptibleSleepFinish(false)
		return nil, err
	}
	// Then we need to walk to the file we just created to get a non-open fid
	// representing it, and to get its metadata. This must use d.file since, as
	// explained above, dirfile was invalidated by dirfile.Create().
	ctx.UninterruptibleSleepStart(false)
	walkQIDs, nonOpenFile, attrMask, attr, err := d.file.WalkGetAttr([]string{childName})
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		mnt.EndWrite()
		ctx.UninterruptibleSleepStart(false)
		openFile.Close()
		if fdobj != nil {
			fdobj.Close()
		}
		ctx.UninterruptibleSleepFinish(false)
		return nil, err
	}
	// Sanity-check that we walked to the file we created.
	if createQID.Path != walkQIDs[0].Path {
		// Probably due to concurrent remote filesystem mutation?
		ctx.Warningf("gofer.dentry.createAndOpenChildLocked: created file has QID %v before walk, QID %v after", createQID, walkQIDs[0])
		mnt.EndWrite()
		ctx.UninterruptibleSleepStart(false)
		nonOpenFile.Close()
		openFile.Close()
		if fdobj != nil {
			fdobj.Close()
		}
		ctx.UninterruptibleSleepFinish(false)
		return nil, syserror.EAGAIN
	}

	// Construct the new dentry.
	child, err := d.fs.newDentry(ctx, nonOpenFile, createQID, attrMask, &attr)
	if err != nil {
		mnt.EndWrite()
		ctx.UninterruptibleSleepStart(false)
		nonOpenFile.Close()
		openFile.Close()
		if fdobj != nil {
			fdobj.Close()
		}
		ctx.UninterruptibleSleepFinish(false)
		return nil, err
	}
	// Take a reference on the new dentry to be held by the new file
	// description. (This reference also means that the new dentry is not
	// eligible for caching yet, so we don't need to append to a dentryBuffer.)
	child.refs = 1
	// Incorporate the fid that was opened by lcreate.
	// FIXME(jamieliu): specialRegularFiles
	//
	readable := vfs.MayReadFileWithOpenFlags(opts.Flags)
	writable := vfs.MayWriteFileWithOpenFlags(opts.Flags)
	child.handleMu.Lock()
	child.handle.file = openFile
	if fdobj != nil {
		child.handle.fd = int32(fdobj.Release())
	}
	child.handleReadable = readable
	child.handleWritable = writable
	child.handleMu.Unlock()
	// ... and insert it into the dentry tree.
	d.incRefLocked() // reference held by child on its parent d
	d.vfsd.InsertChild(&child.vfsd, childName)
	delete(d.negativeChildren, childName)
	d.dirents = nil

	// Finally, construct a file description representing the created file.
	fd := &regularFileFD{
		fileDescription: fileDescription{
			flags: opts.Flags,
		},
		readable: readable,
		writable: writable,
	}
	mnt.IncRef()
	fd.vfsfd.Init(fd, mnt, &child.vfsd)
	// If the created file is writable, the call to mnt.CheckBeginWrite() near
	// the beginning of this function pairs with the mnt.EndWrite() in
	// regularFileFD.Release().
	if !writable {
		mnt.EndWrite()
	}
	return &fd.vfsfd, nil
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	var db *dentryBuffer
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndRelease(&db)
	d, err := fs.walkExistingLocked(ctx, rp, &db)
	if err != nil {
		return "", err
	}
	if !d.isSymlink() {
		return "", syserror.EINVAL
	}
	return d.readlink(ctx, fs, rp.Mount())
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry, opts vfs.RenameOptions) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	var db *dentryBuffer
	fs.renameMu.RLock()
	defer fs.renameMuRUnlockAndRelease(&db)
	d, err := fs.walkExistingLocked(ctx, rp, &db)
	if err != nil {
		return linux.Statx{}, err
	}
	// Since walking updates metadata for all traversed dentries under
	// InteropModeShared, including the returned one, we can return cached
	// metadata here regardless of fs.opts.interop.
	var stat linux.Statx
	d.statTo(&stat)
	return stat, nil
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	// FIXME(jamieliu): implement
	return linux.Statfs{}, syserror.ENOSYS
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	// FIXME(jamieliu): implement
	return syserror.ENOSYS
}

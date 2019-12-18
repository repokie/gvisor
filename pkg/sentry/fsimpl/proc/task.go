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

package proc

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// taskInode represents the inode for /proc/PID/ directory.
//
// +stateify savable
type taskInode struct {
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNoDynamicLookup
	kernfs.InodeAttrs
	kernfs.OrderedChildren

	task *kernel.Task
}

var _ kernfs.Inode = (*taskInode)(nil)

func newTaskInode(inoGen InoGenerator, task *kernel.Task, pidns *kernel.PIDNamespace, isThreadGroup bool, cgroupControllers map[string]string) *kernfs.Dentry {
	contents := map[string]*kernfs.Dentry{
		"auxv":    newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &auxvData{task: task}),
		"cmdline": newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &cmdlineData{task: task, arg: cmdlineDataArg}),
		"comm":    newComm(task, inoGen.NextIno(), filePerm),
		"environ": newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &cmdlineData{task: task, arg: environDataArg}),
		//"exe":       newExe(t, msrc),
		//"fd":        newFdDir(t, msrc),
		//"fdinfo":    newFdInfoDir(t, msrc),
		"gid_map": newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &idMapData{task: task, gids: true}),
		"io":      newTaskOwnedFile(task, inoGen.NextIno(), filePerm, newIO(task, isThreadGroup)),
		"maps":    newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &mapsData{mapsCommon{task: task}}),
		//"mountinfo": seqfile.NewSeqFileInode(t, &mountInfoFile{t: t}, msrc),
		//"mounts":    seqfile.NewSeqFileInode(t, &mountsFile{t: t}, msrc),
		"ns": newTaskOwnedDir(task, inoGen.NextIno(), 0511, map[string]*kernfs.Dentry{
			"net":  newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &namespaceData{ns: "net", ino: inoGen.NextIno()}),
			"pid":  newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &namespaceData{ns: "pid", ino: inoGen.NextIno()}),
			"user": newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &namespaceData{ns: "user", ino: inoGen.NextIno()}),
		}),
		"smaps":   newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &smapsData{mapsCommon{task: task}}),
		"stat":    newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &taskStatData{task: task, pidns: pidns, tgstats: isThreadGroup}),
		"statm":   newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &statmData{task: task}),
		"status":  newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &statusData{task: task, pidns: pidns}),
		"uid_map": newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &idMapData{task: task, gids: false}),
	}
	if isThreadGroup {
		dentry := newSubtasks(task, pidns, inoGen, cgroupControllers)
		contents["task"] = dentry
	}
	if len(cgroupControllers) > 0 {
		contents["cgroup"] = newTaskOwnedFile(task, inoGen.NextIno(), filePerm, &cgroupData{controllers: cgroupControllers})
	}

	taskInode := &taskInode{task: task}
	// Note: credentials are overridden by taskOwnedInode.
	taskInode.InodeAttrs.Init(task.Credentials(), inoGen.NextIno(), linux.ModeDirectory|dirPerm)

	inode := &taskOwnedInode{Inode: taskInode, owner: task}
	dentry := &kernfs.Dentry{}
	dentry.Init(inode)

	taskInode.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	links := taskInode.OrderedChildren.Populate(dentry, contents)
	taskInode.IncLinks(links)

	return dentry
}

// Valid implements kernfs.inodeDynamicLookup. This inode remains valid as long
// as the task is still running. When it's dead, another tasks with the same
// PID could replace it.
func (i *taskInode) Valid(ctx context.Context) bool {
	return i.task.ExitState() != kernel.TaskExitDead
}

// Open implements kernfs.Inode.
func (i *taskInode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	fd := &kernfs.GenericDirectoryFD{}
	fd.Init(rp.Mount(), vfsd, &i.OrderedChildren, flags)
	return fd.VFSFileDescription(), nil
}

// SetStat implements kernfs.Inode.
func (i *taskInode) SetStat(_ *vfs.Filesystem, opts vfs.SetStatOptions) error {
	stat := opts.Stat
	if stat.Mask&linux.STATX_MODE != 0 {
		return syserror.EPERM
	}
	return nil
}

// taskOwnedInode implements kernfs.Inode and overrides inode owner with task
// effective user and group.
type taskOwnedInode struct {
	kernfs.Inode

	// owner is the task that owns this inode.
	owner *kernel.Task
}

var _ kernfs.Inode = (*taskOwnedInode)(nil)

func newTaskOwnedFile(task *kernel.Task, ino uint64, perm linux.FileMode, data vfs.DynamicBytesSource) *kernfs.Dentry {
	dynFile := &kernfs.DynamicBytesFile{}

	// Note: credentials are overridden by taskOwnedInode.
	dynFile.Init(task.Credentials(), ino, data, perm)

	inode := &taskOwnedInode{Inode: dynFile, owner: task}
	d := &kernfs.Dentry{}
	d.Init(inode)
	return d
}

func newTaskOwnedDir(task *kernel.Task, ino uint64, perm linux.FileMode, children map[string]*kernfs.Dentry) *kernfs.Dentry {
	dir := &kernfs.StaticDirectory{}

	// Note: credentials are overridden by taskOwnedInode.
	dir.Init(task.Credentials(), ino, perm)

	inode := &taskOwnedInode{Inode: dir, owner: task}
	d := &kernfs.Dentry{}
	d.Init(inode)

	dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	links := dir.OrderedChildren.Populate(d, children)
	dir.IncLinks(links)

	return d
}

// Stat implements kernfs.Inode.
func (i *taskOwnedInode) Stat(fs *vfs.Filesystem) linux.Statx {
	stat := i.Inode.Stat(fs)
	uid, gid := i.getOwner(linux.FileMode(stat.Mode))
	stat.UID = uint32(uid)
	stat.GID = uint32(gid)
	return stat
}

// CheckPermissions implements kernfs.Inode.
func (i *taskOwnedInode) CheckPermissions(_ context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	mode := i.Mode()
	uid, gid := i.getOwner(mode)
	return vfs.GenericCheckPermissions(
		creds,
		ats,
		mode.FileType() == linux.ModeDirectory,
		uint16(mode),
		uid,
		gid,
	)
}

func (i *taskOwnedInode) getOwner(mode linux.FileMode) (auth.KUID, auth.KGID) {
	// By default, set the task owner as the file owner.
	creds := i.owner.Credentials()
	uid := creds.EffectiveKUID
	gid := creds.EffectiveKGID

	// Linux doesn't apply dumpability adjustments to world readable/executable
	// directories so that applications can stat /proc/PID to determine the
	// effective UID of a process. See fs/proc/base.c:task_dump_owner.
	if mode.FileType() == linux.ModeDirectory && mode.Permissions() == 0555 {
		return uid, gid
	}

	// If the task is not dumpable, then root (in the namespace preferred)
	// owns the file.
	var m *mm.MemoryManager
	i.owner.WithMuLocked(func(t *kernel.Task) {
		m = t.MemoryManager()
	})

	if m == nil {
		return auth.RootKUID, auth.RootKGID
	}
	if m.Dumpability() != mm.UserDumpable {
		uid = auth.RootKUID
		if kuid := creds.UserNamespace.MapToKUID(auth.RootUID); kuid.Ok() {
			uid = kuid
		}
		gid = auth.RootKGID
		if kgid := creds.UserNamespace.MapToKGID(auth.RootGID); kgid.Ok() {
			gid = kgid
		}
	}
	return uid, gid
}

func newIO(t *kernel.Task, isThreadGroup bool) *ioData {
	if isThreadGroup {
		return &ioData{t.ThreadGroup()}
	}
	return &ioData{t}
}

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

package devtmpfs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func TestDevtmpfs(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := vfs.New()
	// Register tmpfs just so that we can have a root filesystem that isn't
	// devtmpfs.
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	vfsObj.MustRegisterFilesystemType("devtmpfs", &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	// Create a test mount namespace with devtmpfs mounted at "/dev".
	const devPath = "/dev"
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "tmpfs" /* source */, "tmpfs" /* fsTypeName */, &vfs.GetFilesystemOptions{})
	if err != nil {
		t.Fatalf("failed to create tmpfs root mount: %v", err)
	}
	defer mntns.DecRef(vfsObj)
	root := mntns.Root()
	defer root.DecRef()
	devpop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(devPath),
	}
	if err := vfsObj.MkdirAt(ctx, creds, &devpop, &vfs.MkdirOptions{
		Mode: 0755,
	}); err != nil {
		t.Fatalf("failed to create mount point: %v", err)
	}
	if err := vfsObj.MountAt(ctx, creds, "devtmpfs" /* source */, &devpop, "devtmpfs" /* fsTypeName */, &vfs.MountOptions{}); err != nil {
		t.Fatalf("failed to mount devtmpfs: %v", err)
	}

	// Create a dummy device special file using a devtmpfs.Accessor.
	a, err := NewAccessor(ctx, vfsObj, creds, "devtmpfs")
	if err != nil {
		t.Fatalf("failed to create devtmpfs.Accessor: %v", err)
	}
	defer a.Release()
	const (
		pathInDev = "dummy"
		kind      = vfs.CharDevice
		major     = 12
		minor     = 34
		perms     = 0600
		wantMode  = linux.S_IFCHR | perms
	)
	if err := a.CreateFile(ctx, pathInDev, kind, major, minor, perms); err != nil {
		t.Fatalf("failed to create device file: %v", err)
	}

	// The device special file should be visible in the test mount namespace.
	abspath := devPath + "/" + pathInDev
	stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(abspath),
	}, &vfs.StatOptions{
		Mask: linux.STATX_TYPE | linux.STATX_MODE,
	})
	if err != nil {
		t.Fatalf("failed to stat device file at %s: %v", abspath, err)
	}
	if stat.Mode != wantMode {
		t.Errorf("device file mode: got %v, wanted %v", stat.Mode, wantMode)
	}
	if stat.RdevMajor != major {
		t.Errorf("major device number: got %v, wanted %v", stat.RdevMajor, major)
	}
	if stat.RdevMinor != minor {
		t.Errorf("minor device number: got %v, wanted %v", stat.RdevMinor, minor)
	}
}

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

package linux

// Constants from asm-generic/ioctl.h.
const (
	iocNrBits   = 8
	iocTypeBits = 8
	iocSizeBits = 14
	iocDirBits  = 2

	iocNrShift   = 0
	iocTypeShift = iocNrShift + iocNrBits
	iocSizeShift = iocTypeShift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits
)

// IocDir is IOC_* constants from asm-generic/ioctl.h.
type IocDir uint32

// Constants from asm-generic/ioctl.h.
const (
	IocDirNone IocDir = iota
	IocDirWrite
	IocDirRead
)

// IOC outputs the result of _IOC macro in asm-generic/ioctl.h.
func IOC(dir IocDir, typ, nr, size uint32) uint32 {
	return uint32(dir)<<iocDirShift | typ<<iocTypeShift | nr<<iocNrShift | size<<iocSizeShift
}

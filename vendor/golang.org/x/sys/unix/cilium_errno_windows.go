// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

// This file is not part of upstream golang.org/x/sys/unix. It provides the
// handful of Linux errno constants that Cilium's cross-platform BPF code
// references at compile time on Windows. Values match the Linux ABI and are
// exposed as syscall.Errno so they remain usable with errors.Is.

package unix

import "syscall"

const (
	ENOSPC  = syscall.Errno(0x1c)
	ENOENT  = syscall.Errno(0x2)
	EBADFD  = syscall.Errno(0x4d)
	EBADF   = syscall.Errno(0x9)
	EINVAL  = syscall.Errno(0x16)
	EPERM   = syscall.Errno(0x1)
	ENOLINK = syscall.Errno(0x43)
)

const (
	IFNAMSIZ = 16
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

// This file is not part of upstream golang.org/x/sys/unix. It provides the
// small set of Linux BPF ABI flag constants that Cilium's cross-platform code
// (e.g. the generated datapath map specs) references at compile time on
// Windows. The values match the Linux UAPI (include/uapi/linux/bpf.h) and are
// stable ABI constants.

package unix

const (
	BPF_F_NO_PREALLOC   = 0x1
	BPF_F_NO_COMMON_LRU = 0x2
	BPF_F_RDONLY_PROG   = 0x80
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bpfabi

// BPF map-creation flag values from the Linux UAPI (include/uapi/linux/bpf.h).
// These are provided as literals on non-Linux platforms where
// golang.org/x/sys/unix does not define them. The values are part of the
// stable kernel ABI and must not change.
const (
	// NoPrealloc corresponds to BPF_F_NO_PREALLOC.
	NoPrealloc = 0x1
	// NoCommonLRU corresponds to BPF_F_NO_COMMON_LRU.
	NoCommonLRU = 0x2
	// RdonlyProg corresponds to BPF_F_RDONLY_PROG.
	RdonlyProg = 0x80
)

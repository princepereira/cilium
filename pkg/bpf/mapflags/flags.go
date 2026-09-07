// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package mapflags defines platform-independent BPF map creation flags.
//
// These mirror the kernel's BPF_F_* UAPI values but are defined here as plain
// numeric constants so that map specifications can be built on any OS (e.g.
// Linux and Windows) without importing the Linux-specific
// golang.org/x/sys/unix package. It is intentionally a dependency-free leaf
// package so it can be imported from any layer without creating import cycles.
package mapflags

const (
	// BPF_F_NO_PREALLOC disables preallocation of map memory.
	BPF_F_NO_PREALLOC = 0x1
	// BPF_F_NO_COMMON_LRU uses a distributed (per-CPU) LRU instead of a common LRU.
	BPF_F_NO_COMMON_LRU = 0x2
	// BPF_F_RDONLY_PROG makes the map read-only from the BPF program side.
	BPF_F_RDONLY_PROG = 0x80
	// BPF_F_XDP_HAS_FRAGS indicates the program can process multi-buffer XDP frames.
	BPF_F_XDP_HAS_FRAGS = 0x20
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// Package bpfabi exposes a small, dependency-free set of BPF map-creation
// flag values used across Cilium's map packages. On Linux the values are
// sourced from golang.org/x/sys/unix so they always match the running
// kernel's UAPI. On non-Linux platforms (where x/sys/unix is empty) the
// same constants are provided as literals with the well-known ABI values.
//
// This package MUST remain a leaf (import only x/sys/unix on Linux, nothing
// elsewhere) so that map packages such as pkg/datapath/maps can depend on it
// without creating an import cycle with pkg/bpf.
package bpfabi

import "golang.org/x/sys/unix"

const (
	// NoPrealloc corresponds to BPF_F_NO_PREALLOC.
	NoPrealloc = unix.BPF_F_NO_PREALLOC
	// NoCommonLRU corresponds to BPF_F_NO_COMMON_LRU.
	NoCommonLRU = unix.BPF_F_NO_COMMON_LRU
	// RdonlyProg corresponds to BPF_F_RDONLY_PROG.
	RdonlyProg = unix.BPF_F_RDONLY_PROG
)

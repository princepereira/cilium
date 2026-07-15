// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package unix

// This file is a Cilium Windows-port addition. golang.org/x/sys/unix does not
// build a full package on Windows, so the BPF map-creation flag constants
// referenced by Cilium's BPF map specifications are undefined there. These are
// stable Linux UAPI values and only affect BPF map creation, which is a no-op
// on Windows; defining them here lets the map-spec packages compile.
const (
	// BPF_F_NO_PREALLOC disables pre-allocation of map elements.
	BPF_F_NO_PREALLOC = 0x1

	// BPF_F_NO_COMMON_LRU uses a separate LRU list per CPU.
	BPF_F_NO_COMMON_LRU = 0x2

	// BPF_F_RDONLY_PROG marks a map as read-only from the BPF program side.
	BPF_F_RDONLY_PROG = 0x80
)

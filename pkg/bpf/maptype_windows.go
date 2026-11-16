// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import "github.com/cilium/ebpf"

// ToPlatformMapType translates a cilium Linux-tagged ebpf.MapType into the
// equivalent Windows-tagged constant understood by eBPF-for-Windows.
//
// cilium/ebpf tags every map type constant with a platform in its high bits
// (see internal/platform). Cilium's map specs are written with the Linux
// constants (e.g. ebpf.LPMTrie), but on the native Windows platform
// cilium/ebpf's map creation rejects any type whose platform tag is not the
// running platform. The low bits also differ between the two enumerations
// (e.g. Linux LPMTrie == 11 vs WindowsLPMTrie == WindowsTag|9), so an explicit
// name-based mapping is required rather than a simple re-tag.
//
// Types without a Windows equivalent (for example PerfEventArray) are returned
// unchanged; their creation is expected to be handled/no-op'd at a higher layer
// (e.g. the events map).
func ToPlatformMapType(t ebpf.MapType) ebpf.MapType {
	switch t {
	case ebpf.Hash:
		return ebpf.WindowsHash
	case ebpf.Array:
		return ebpf.WindowsArray
	case ebpf.ProgramArray:
		return ebpf.WindowsProgramArray
	case ebpf.PerCPUHash:
		return ebpf.WindowsPerCPUHash
	case ebpf.PerCPUArray:
		return ebpf.WindowsPerCPUArray
	case ebpf.HashOfMaps:
		return ebpf.WindowsHashOfMaps
	case ebpf.ArrayOfMaps:
		return ebpf.WindowsArrayOfMaps
	case ebpf.LRUHash:
		return ebpf.WindowsLRUHash
	case ebpf.LRUCPUHash:
		return ebpf.WindowsLRUCPUHash
	case ebpf.LPMTrie:
		return ebpf.WindowsLPMTrie
	case ebpf.Queue:
		return ebpf.WindowsQueue
	case ebpf.Stack:
		return ebpf.WindowsStack
	case ebpf.RingBuf:
		return ebpf.WindowsRingBuf
	default:
		// Already Windows-tagged (idempotent) or no Windows equivalent.
		return t
	}
}

// ToPlatformMapFlags drops the Linux map-creation flags on Windows. eBPF-for-
// Windows does not accept the Linux BPF_F_* map flags (for example
// BPF_F_NO_PREALLOC or BPF_F_RDONLY_PROG) and fails map creation with EINVAL
// when any are set; it manages its own allocation, so none of these flags
// apply. Returning 0 lets the map be created with the same key/value geometry.
func ToPlatformMapFlags(flags uint32) uint32 {
	return 0
}

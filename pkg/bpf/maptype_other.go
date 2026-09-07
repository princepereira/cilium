// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package bpf

import "github.com/cilium/ebpf"

// ToPlatformMapType returns the map type unchanged on non-Windows platforms,
// where cilium's Linux-tagged ebpf.MapType constants are already native.
func ToPlatformMapType(t ebpf.MapType) ebpf.MapType {
	return t
}

// ToPlatformMapFlags returns the map creation flags unchanged on non-Windows
// platforms.
func ToPlatformMapFlags(flags uint32) uint32 {
	return flags
}

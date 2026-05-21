// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import "fmt"

// MapKey is a stub interface for Windows builds.
// On Linux this is backed by eBPF map keys; on Windows, networking is handled via HNS/HCN APIs.
type MapKey interface {
	fmt.Stringer
	New() MapKey
}

// MapValue is a stub interface for Windows builds.
// On Linux this is backed by eBPF map values; on Windows, networking is handled via HNS/HCN APIs.
type MapValue interface {
	fmt.Stringer
	New() MapValue
}

// Map is a stub type for Windows builds.
// On Linux this wraps a kernel eBPF map; on Windows, load-balancing state is managed by HNS.
type Map struct {
	name string
}

// Name returns the name of the map.
func (m *Map) Name() string {
	return m.name
}

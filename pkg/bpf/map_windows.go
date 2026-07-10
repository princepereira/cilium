// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"errors"
	"log/slog"
)

// This file provides the platform-neutral surface of pkg/bpf that the Windows
// datapath (CNC) needs. On Windows there is no eBPF, so the concrete map
// implementation (map_linux.go and friends) is not compiled. Instead we expose
// the interfaces (MapKey/MapValue) that describe BPF map serialization layouts
// -- these are still used to model the CNC/StateDB data -- and a minimal Map
// type so that platform-neutral signatures referencing *bpf.Map continue to
// compile. The Map type has no behaviour on Windows; callers use the CNC-backed
// implementations (e.g. CNCLBMaps) instead of programming BPF maps directly.

var (
	// ErrMaxLookup is returned when the maximum number of map element lookups
	// has been reached. Mirrored from the Linux implementation so that
	// platform-neutral callers can reference it.
	ErrMaxLookup = errors.New("maximum number of lookups reached")
)

// MapKey is the interface implemented by types that model the key layout of a
// BPF map. On Windows these layouts are retained for parity with Linux (byte
// order, sizes) even though the datapath is CNC-backed rather than eBPF.
type MapKey interface {
	// String returns a human readable representation of the key.
	String() string

	// New must return a pointer to a new MapKey.
	New() MapKey
}

// MapValue is the interface implemented by types that model the value layout of
// a BPF map. See MapKey for the Windows semantics.
type MapValue interface {
	// String returns a human readable representation of the value.
	String() string

	// New must return a pointer to a new MapValue.
	New() MapValue
}

// MapPerCPUValue is the same as MapValue, but for per-CPU maps.
type MapPerCPUValue interface {
	MapValue

	// NewSlice must return a pointer to a slice of structs that implement
	// MapValue.
	NewSlice() any
}

// Map is a placeholder for the Linux BPF map type. On Windows it carries no
// behaviour; it exists so that platform-neutral code referencing *bpf.Map (for
// example as a return type) compiles. The Windows datapath never programs BPF
// maps -- it uses the CNC datapath instead.
type Map struct {
	Logger *slog.Logger

	name string
	path string
}

// Name returns the name of the map.
func (m *Map) Name() string {
	if m == nil {
		return ""
	}
	return m.name
}

// NonPrefixedName returns the name of the map without the "cilium_" prefix.
func (m *Map) NonPrefixedName() string {
	if m == nil {
		return ""
	}
	return extractCommonName(m.name)
}

// IsOpen reports whether the map is open. On Windows a placeholder Map is never
// open.
func (m *Map) IsOpen() bool {
	return false
}

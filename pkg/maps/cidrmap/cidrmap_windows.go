// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cidrmap

import "net"

const (
	// MapName is the prefix for CIDR maps.
	MapName = "cilium_cidr_"

	// MaxEntries is the maximum number of entries in CIDR maps.
	MaxEntries = 16384

	// LPM_MAP_VALUE_SIZE is the size of the value in LPM trie maps.
	LPM_MAP_VALUE_SIZE = 1
)

// CIDRMap provides a stub for CIDR map operations on Windows.
type CIDRMap struct {
	name string
}

// OpenMapElems opens a CIDR map (stub on Windows).
func OpenMapElems(name string, prefixLen int, prefixDyn int, maxEntries int) (*CIDRMap, error) {
	return &CIDRMap{name: name}, nil
}

// InsertCIDR inserts a CIDR into the map (stub on Windows).
func (m *CIDRMap) InsertCIDR(cidr net.IPNet) error {
	return nil
}

// DeleteCIDR deletes a CIDR from the map (stub on Windows).
func (m *CIDRMap) DeleteCIDR(cidr net.IPNet) error {
	return nil
}

// CIDRExists checks if a CIDR exists in the map (stub on Windows).
func (m *CIDRMap) CIDRExists(cidr net.IPNet) bool {
	return false
}

// CIDRNext returns the next CIDR in the map (stub on Windows).
func (m *CIDRMap) CIDRNext(cidr net.IPNet) *net.IPNet {
	return nil
}

// CIDRDump dumps the map contents (stub on Windows).
func (m *CIDRMap) CIDRDump() ([]string, error) {
	return nil, nil
}

// String returns the map name.
func (m *CIDRMap) String() string {
	return m.name
}

// Close closes the map (no-op on Windows).
func (m *CIDRMap) Close() error {
	return nil
}

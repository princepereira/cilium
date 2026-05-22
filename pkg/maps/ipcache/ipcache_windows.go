// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ipcache

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
	"github.com/cilium/cilium/pkg/metrics"
)

// CNCMap implements the ipcache Map operations using cncshim on Windows.
type CNCMap struct {
	client *winDatapath.CNCClient
	mu     sync.RWMutex
	// In-memory cache for dump operations
	entries map[string]RemoteEndpointInfo // key string -> value
}

// NewCNCMap creates a new Windows CNC-backed ipcache map.
func NewCNCMap(client *winDatapath.CNCClient) *CNCMap {
	return &CNCMap{
		client:  client,
		entries: make(map[string]RemoteEndpointInfo),
	}
}

// Update implements the Map interface for Windows using cncshim SetIdentity.
func (m *CNCMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipcKey, ok := key.(*Key)
	if !ok {
		return fmt.Errorf("unexpected key type %T", key)
	}

	ipcVal, ok := value.(*RemoteEndpointInfo)
	if !ok {
		return fmt.Errorf("unexpected value type %T", value)
	}

	prefix := ipcKey.Prefix()
	identity := ipcVal.SecurityIdentity

	api := m.client.API()
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}

	if err := api.SetIdentity(prefix, identity); err != nil {
		return fmt.Errorf("CNC SetIdentity(%s, %d): %w", prefix, identity, err)
	}

	m.entries[ipcKey.String()] = *ipcVal
	return nil
}

// Delete implements the Map interface for Windows using cncshim DeleteIdentity.
func (m *CNCMap) Delete(key bpf.MapKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipcKey, ok := key.(*Key)
	if !ok {
		return fmt.Errorf("unexpected key type %T", key)
	}

	prefix := ipcKey.Prefix()

	api := m.client.API()
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}

	if err := api.DeleteIdentity(prefix); err != nil {
		return fmt.Errorf("CNC DeleteIdentity(%s): %w", prefix, err)
	}

	delete(m.entries, ipcKey.String())
	return nil
}

// Lookup queries the identity for a given prefix via cncshim.
func (m *CNCMap) Lookup(prefix netip.Prefix) (uint32, error) {
	api := m.client.API()
	if api == nil {
		return 0, fmt.Errorf("CNC API client not initialized")
	}
	return api.GetIdentity(prefix)
}

// IPCacheMap gets the ipcache Map for Windows. On Windows this returns nil
// as the CNCMap is used through the datapath ipcache listener instead.
func IPCacheMap(registry *metrics.Registry) *Map {
	// On Windows, the BPF-based Map is not used.
	// The CNCMap is provided separately via the Windows datapath cell.
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/princepereira/cncshim/pkg/cncapi"
)

// CNCLBMaps implements the LBMaps interface using cncshim for Windows.
type CNCLBMaps struct {
	mu     sync.RWMutex
	client *winDatapath.CNCClient
	log    *slog.Logger

	// In-memory state tracking for dump/lookup operations
	services    map[string]serviceEntry
	backends    map[uint32]backendEntry
	revNats     map[uint16]revNatEntry
	affinities  map[string]*AffinityMatchValue
	sourceRange map[string]*SourceRangeValue
}

type serviceEntry struct {
	key   ServiceKey
	value ServiceValue
}

type backendEntry struct {
	key   BackendKey
	value BackendValue
}

type revNatEntry struct {
	key   RevNatKey
	value RevNatValue
}

func newCNCLBMaps(p lbmapsParams) bpf.MapOut[LBMaps] {
	r := &CNCLBMaps{
		log:         p.Log,
		services:    make(map[string]serviceEntry),
		backends:    make(map[uint32]backendEntry),
		revNats:     make(map[uint16]revNatEntry),
		affinities:  make(map[string]*AffinityMatchValue),
		sourceRange: make(map[string]*SourceRangeValue),
	}
	return bpf.NewMapOut(LBMaps(r))
}

func (m *CNCLBMaps) SetClient(client *winDatapath.CNCClient) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.client = client
}

func (m *CNCLBMaps) IsEmpty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.services) == 0 && len(m.backends) == 0
}

// serviceKeyStr returns a string key for the in-memory service map.
func serviceKeyStr(key ServiceKey) string {
	return fmt.Sprintf("%s:%d:%d:%d", key.GetAddress(), key.GetPort(), key.GetProtocol(), key.GetBackendSlot())
}

// UpdateService implements LBMaps.
func (m *CNCLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store in local state
	k := serviceKeyStr(key)
	m.services[k] = serviceEntry{key: key, value: value}

	// Only push master entries (slot 0) to CNC as service definitions
	if key.GetBackendSlot() == 0 {
		api := m.client.API()
		if api == nil {
			return fmt.Errorf("CNC API client not initialized")
		}

		frontend := cncapi.FrontendInfo{
			IPAddress: key.GetAddress(),
			Port:      key.GetPort(),
			Protocol:  key.GetProtocol(),
		}

		lbInfo := &cncapi.LoadBalancerInfo{
			ServiceType:            cncapi.ServiceTypeClusterIP,
			Frontend:               frontend,
			AffinityTimeoutSeconds: value.GetSessionAffinityTimeoutSec(),
		}

		serviceID := uint16(value.GetRevNat())
		err := api.CreateLoadBalancerService(serviceID, lbInfo)
		if err != nil {
			return fmt.Errorf("CNC CreateLoadBalancerService: %w", err)
		}
	}

	return nil
}

// DeleteService implements LBMaps.
func (m *CNCLBMaps) DeleteService(key ServiceKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := serviceKeyStr(key)
	entry, exists := m.services[k]
	delete(m.services, k)

	// Only delete master entries from CNC
	if exists && key.GetBackendSlot() == 0 {
		api := m.client.API()
		if api == nil {
			return nil
		}

		serviceID := uint16(entry.value.GetRevNat())
		lbInfo := &cncapi.LoadBalancerInfo{
			Frontend: cncapi.FrontendInfo{
				IPAddress: key.GetAddress(),
				Port:      key.GetPort(),
				Protocol:  key.GetProtocol(),
			},
		}
		if err := api.DeleteLoadBalancerService(serviceID, lbInfo); err != nil {
			return fmt.Errorf("CNC DeleteLoadBalancerService: %w", err)
		}
	}

	return nil
}

// DumpService implements LBMaps.
func (m *CNCLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.services {
		cb(e.key, e.value)
	}
	return nil
}

// UpdateBackend implements LBMaps.
func (m *CNCLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uint32(key.GetID())
	m.backends[id] = backendEntry{key: key, value: value}

	api := m.client.API()
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}

	backends := []cncapi.BackendInfo{
		{
			BackendID: id,
			IPAddress: value.GetAddress().Addr(),
			Port:      value.GetPort(),
		},
	}

	err := api.CreateLoadBalancerBackends(backends)
	if err != nil {
		return fmt.Errorf("CNC CreateLoadBalancerBackends: %w", err)
	}

	return nil
}

// DeleteBackend implements LBMaps.
func (m *CNCLBMaps) DeleteBackend(key BackendKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uint32(key.GetID())
	delete(m.backends, id)

	api := m.client.API()
	if api == nil {
		return nil
	}

	// Determine address family from key type
	var af uint16
	switch key.(type) {
	case *Backend4KeyV3:
		af = 4
	case *Backend6KeyV3:
		af = 6
	default:
		af = 4
	}

	err := api.DeleteLoadBalancerBackends(af, []uint32{id})
	if err != nil {
		return fmt.Errorf("CNC DeleteLoadBalancerBackends: %w", err)
	}

	return nil
}

// DumpBackend implements LBMaps.
func (m *CNCLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.backends {
		cb(e.key, e.value)
	}
	return nil
}

// LookupBackend implements LBMaps.
func (m *CNCLBMaps) LookupBackend(key BackendKey) (BackendValue, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id := uint32(key.GetID())
	if e, ok := m.backends[id]; ok {
		return e.value, nil
	}
	return nil, fmt.Errorf("backend %d not found", id)
}

// UpdateRevNat implements LBMaps.
func (m *CNCLBMaps) UpdateRevNat(key RevNatKey, value RevNatValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// RevNat is tracked in-memory; CNC handles this implicitly via service operations
	id := uint16(key.GetKey())
	m.revNats[id] = revNatEntry{key: key, value: value}
	return nil
}

// DeleteRevNat implements LBMaps.
func (m *CNCLBMaps) DeleteRevNat(key RevNatKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uint16(key.GetKey())
	delete(m.revNats, id)
	return nil
}

// DumpRevNat implements LBMaps.
func (m *CNCLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, e := range m.revNats {
		cb(e.key, e.value)
	}
	return nil
}

// UpdateAffinityMatch implements LBMaps.
func (m *CNCLBMaps) UpdateAffinityMatch(key *AffinityMatchKey, value *AffinityMatchValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.affinities[key.String()] = value
	return nil
}

// DeleteAffinityMatch implements LBMaps.
func (m *CNCLBMaps) DeleteAffinityMatch(key *AffinityMatchKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.affinities, key.String())
	return nil
}

// DumpAffinityMatch implements LBMaps.
func (m *CNCLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	// Affinity match is not directly supported by CNC; return empty for now
	return nil
}

// UpdateSourceRange implements LBMaps.
func (m *CNCLBMaps) UpdateSourceRange(key SourceRangeKey, value *SourceRangeValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sourceRange[key.String()] = value
	return nil
}

// DeleteSourceRange implements LBMaps.
func (m *CNCLBMaps) DeleteSourceRange(key SourceRangeKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sourceRange, key.String())
	return nil
}

// DumpSourceRange implements LBMaps.
func (m *CNCLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	return nil
}

// UpdateMaglev implements LBMaps.
// Maglev is not supported on Windows CNC; this is a no-op.
func (m *CNCLBMaps) UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	return nil
}

// DeleteMaglev implements LBMaps.
func (m *CNCLBMaps) DeleteMaglev(key MaglevOuterKey, ipv6 bool) error {
	return nil
}

// DumpMaglev implements LBMaps.
func (m *CNCLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	return nil
}

// UpdateSockRevNat implements LBMaps.
// Socket-level RevNat is not applicable on Windows.
func (m *CNCLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	return nil
}

// DeleteSockRevNat implements LBMaps.
func (m *CNCLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	return nil
}

// ExistsSockRevNat implements LBMaps.
func (m *CNCLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	return false
}

// SockRevNat implements LBMaps.
// Returns nil maps as socket-level RevNat is not applicable on Windows.
func (m *CNCLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) {
	return nil, nil
}

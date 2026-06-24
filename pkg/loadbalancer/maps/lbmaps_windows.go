// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/princepereira/cncshim/pkg/cncapi"
)

// CNCLBMaps implements the LBMaps interface using cncshim for Windows.
type CNCLBMaps struct {
	mu  sync.RWMutex
	api cncapi.CNCApi
	log *slog.Logger

	// In-memory state tracking for dump/lookup operations
	services    map[string]serviceEntry
	backends    map[uint32]backendEntry
	revNats     map[uint16]revNatEntry
	affinities  map[string]*AffinityMatchValue
	sourceRange map[string]*SourceRangeValue

	// pendingSlots accumulates backend IDs written as slot > 0 entries,
	// keyed by service frontend string (addr:port:proto). When the master
	// entry (slot 0) is written, these are used to call
	// UpdateLoadBalancerServiceBackends.
	pendingSlots map[string][]uint32

	// cncBackends tracks what backends CNC currently has associated with
	// each service (keyed by serviceID). Used as "old" parameter in the
	// swap-based UpdateLoadBalancerServiceBackends API.
	cncBackends map[uint16][]cncapi.BackendInfo

	// createdServices tracks which serviceIDs have been created in CNC
	// to avoid re-creating (which wipes backend associations).
	createdServices map[uint16]bool
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
		log:             p.Log,
		services:        make(map[string]serviceEntry),
		backends:        make(map[uint32]backendEntry),
		revNats:         make(map[uint16]revNatEntry),
		affinities:      make(map[string]*AffinityMatchValue),
		sourceRange:     make(map[string]*SourceRangeValue),
		pendingSlots:    make(map[string][]uint32),
		cncBackends:     make(map[uint16][]cncapi.BackendInfo),
		createdServices: make(map[uint16]bool),
	}
	return bpf.NewMapOut(LBMaps(r))
}

func (m *CNCLBMaps) SetAPI(api interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := api.(cncapi.CNCApi); ok {
		m.api = a
	}
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

// frontendKeyStr returns a string key for grouping service slots.
func frontendKeyStr(key ServiceKey) string {
	return fmt.Sprintf("%s:%d:%d", key.GetAddress(), key.GetPort(), key.GetProtocol())
}

// UpdateService implements LBMaps.
func (m *CNCLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Convert from network byte order to host byte order for CNC API
	hostKey := key.ToHost()

	// Store in local state (keep network order for BPF compatibility)
	k := serviceKeyStr(key)
	m.services[k] = serviceEntry{key: key, value: value}

	feKey := frontendKeyStr(key)

	if hostKey.GetBackendSlot() > 0 {
		// Non-master slot: accumulate the backend ID for later association.
		// Slot 1 starts a new reconciliation cycle, so clear previous pending slots.
		if hostKey.GetBackendSlot() == 1 {
			m.pendingSlots[feKey] = m.pendingSlots[feKey][:0]
		}
		beID := uint32(value.GetBackendID())
		m.pendingSlots[feKey] = append(m.pendingSlots[feKey], beID)
		return nil
	}

	// Slot 0 (master entry): create the service and associate backends
	api := m.api
	if api == nil {
		// Clear pending slots since they'll be re-written on retry
		delete(m.pendingSlots, feKey)
		return fmt.Errorf("CNC API client not initialized")
	}

	serviceID := byteorder.NetworkToHost16(uint16(value.GetRevNat()))

	frontend := cncapi.FrontendInfo{
		IPAddress: hostKey.GetAddress(),
		Port:      hostKey.GetPort(),
		Protocol:  hostKey.GetProtocol(),
	}

	lbInfo := &cncapi.LoadBalancerInfo{
		ServiceType:            cncapi.ServiceTypeClusterIP,
		Frontend:               frontend,
		AffinityTimeoutSeconds: value.GetSessionAffinityTimeoutSec(),
	}

	// Create the service if not already created
	if !m.createdServices[serviceID] {
		err := api.CreateLoadBalancerService(serviceID, lbInfo)
		if err != nil {
			if isAlreadyExistsError(err) {
				// Service exists from this same agent run or previous lifecycle.
				// Try delete + recreate to ensure correct frontend mapping.
				delErr := api.DeleteLoadBalancerService(serviceID, lbInfo)
				if delErr != nil {
					m.log.Warn("CNC DeleteLoadBalancerService failed (stale entry)",
						"serviceID", serviceID, "error", delErr)
				}
				err = api.CreateLoadBalancerService(serviceID, lbInfo)
				if err != nil && isAlreadyExistsError(err) {
					// Delete failed and service still exists — accept it and continue
					m.log.Warn("CNC service still exists after delete attempt, continuing",
						"serviceID", serviceID)
				} else if err != nil {
					return fmt.Errorf("CNC CreateLoadBalancerService (retry): %w", err)
				} else {
					m.log.Info("CNC CreateLoadBalancerService recreated",
						"serviceID", serviceID,
						"frontend", fmt.Sprintf("%s:%d/%d", hostKey.GetAddress(), hostKey.GetPort(), hostKey.GetProtocol()))
				}
			} else {
				return fmt.Errorf("CNC CreateLoadBalancerService: %w", err)
			}
		} else {
			m.log.Info("CNC CreateLoadBalancerService succeeded",
				"serviceID", serviceID,
				"frontend", fmt.Sprintf("%s:%d/%d", hostKey.GetAddress(), hostKey.GetPort(), hostKey.GetProtocol()))
		}
		m.createdServices[serviceID] = true
	}

	// Build new backend list from pending slots
	pendingIDs := m.pendingSlots[feKey]
	delete(m.pendingSlots, feKey)

	if len(pendingIDs) == 0 {
		return nil
	}

	newBackends := make([]cncapi.BackendInfo, 0, len(pendingIDs))
	for _, beID := range pendingIDs {
		if be, ok := m.backends[beID]; ok {
			newBackends = append(newBackends, cncapi.BackendInfo{
				BackendID: beID,
				IPAddress: be.value.GetAddress().Addr(),
				Port:      be.value.GetPort(),
			})
		} else {
			// Backend not yet in our local map — use ID only
			newBackends = append(newBackends, cncapi.BackendInfo{
				BackendID: beID,
			})
		}
	}

	// Get old backends (what CNC currently has for this service)
	oldBackends := m.cncBackends[serviceID]

	// Diagnostic: verify service exists in CNC before update
	storedSvc, getErr := api.GetLoadBalancerService(&frontend)
	if getErr != nil {
		m.log.Warn("CNC GetLoadBalancerService failed (pre-update check)",
			"serviceID", serviceID,
			"frontend", fmt.Sprintf("%s:%d/%d", hostKey.GetAddress(), hostKey.GetPort(), hostKey.GetProtocol()),
			"error", getErr)
	} else {
		m.log.Info("CNC GetLoadBalancerService (pre-update check)",
			"serviceID", serviceID,
			"storedServiceType", storedSvc.ServiceType,
			"storedFrontend", fmt.Sprintf("%s:%d/%d", storedSvc.Frontend.IPAddress, storedSvc.Frontend.Port, storedSvc.Frontend.Protocol),
			"storedFlags", storedSvc.ServiceFlags,
			"storedAffinity", storedSvc.AffinityTimeoutSeconds)
	}

	// Diagnostic: verify backends exist in CNC
	beIDs := make([]uint32, len(newBackends))
	for i, b := range newBackends {
		beIDs[i] = b.BackendID
	}
	storedBEs, getBEErr := api.GetLoadBalancerBackends(2, beIDs) // AF_INET=2
	if getBEErr != nil {
		m.log.Warn("CNC GetLoadBalancerBackends failed (pre-update check)",
			"backendIDs", fmt.Sprintf("%v", beIDs),
			"error", getBEErr)
	} else {
		for i, res := range storedBEs {
			m.log.Info("CNC GetLoadBalancerBackends (pre-update check)",
				"index", i,
				"backendID", res.Info.BackendID,
				"address", fmt.Sprintf("%s:%d", res.Info.IPAddress, res.Info.Port),
				"result", res.Result)
		}
	}

	m.log.Info("CNC UpdateLoadBalancerServiceBackends calling",
		"serviceID", serviceID,
		"frontend", fmt.Sprintf("%s:%d/%d", hostKey.GetAddress(), hostKey.GetPort(), hostKey.GetProtocol()),
		"newBackends", len(newBackends),
		"oldBackends", len(oldBackends),
		"newBackendIDs", fmt.Sprintf("%v", pendingIDs))

	// Log exact backend details being passed
	for i, be := range newBackends {
		m.log.Info("CNC UpdateServiceBackends newBackend detail",
			"index", i,
			"backendID", be.BackendID,
			"ip", be.IPAddress.String(),
			"ipIs4", be.IPAddress.Is4(),
			"ipIsValid", be.IPAddress.IsValid(),
			"port", be.Port)
	}

	// Call UpdateLoadBalancerServiceBackends (swap semantics)
	err := api.UpdateLoadBalancerServiceBackends(serviceID, lbInfo, newBackends, oldBackends)
	if err != nil {
		return fmt.Errorf("CNC UpdateLoadBalancerServiceBackends: %w", err)
	}
	m.log.Info("CNC UpdateLoadBalancerServiceBackends succeeded",
		"serviceID", serviceID,
		"frontend", fmt.Sprintf("%s:%d/%d", hostKey.GetAddress(), hostKey.GetPort(), hostKey.GetProtocol()),
		"newBackends", len(newBackends),
		"oldBackends", len(oldBackends))

	// Track what CNC now has
	m.cncBackends[serviceID] = newBackends

	return nil
}

// DeleteService implements LBMaps.
func (m *CNCLBMaps) DeleteService(key ServiceKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Convert from network byte order to host byte order for CNC API
	hostKey := key.ToHost()

	k := serviceKeyStr(key)
	entry, exists := m.services[k]
	delete(m.services, k)

	// Only delete master entries from CNC
	if exists && hostKey.GetBackendSlot() == 0 {
		api := m.api
		if api == nil {
			return nil
		}

		serviceID := byteorder.NetworkToHost16(uint16(entry.value.GetRevNat()))
		lbInfo := &cncapi.LoadBalancerInfo{
			Frontend: cncapi.FrontendInfo{
				IPAddress: hostKey.GetAddress(),
				Port:      hostKey.GetPort(),
				Protocol:  hostKey.GetProtocol(),
			},
		}
		if err := api.DeleteLoadBalancerService(serviceID, lbInfo); err != nil {
			return fmt.Errorf("CNC DeleteLoadBalancerService: %w", err)
		}
		delete(m.createdServices, serviceID)
		delete(m.cncBackends, serviceID)
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

	// Convert from network byte order to host byte order for CNC API
	hostValue := value.ToHost()

	id := uint32(key.GetID())
	// Store host-order value so pending slot lookups get correct port
	m.backends[id] = backendEntry{key: key, value: hostValue}

	api := m.api
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}

	addr := hostValue.GetAddress().Addr()
	port := hostValue.GetPort()

	backends := []cncapi.BackendInfo{
		{
			BackendID: id,
			IPAddress: addr,
			Port:      port,
		},
	}

	err := api.CreateLoadBalancerBackends(backends)
	if err != nil {
		// HRESULT 0x800700B7 = ERROR_ALREADY_EXISTS — stale backend from previous run.
		// Delete the old one and recreate with correct IP/port.
		if isAlreadyExistsError(err) {
			af := uint16(2) // AF_INET
			if addr.Is6() {
				af = 23 // AF_INET6
			}
			_ = api.DeleteLoadBalancerBackends(af, []uint32{id})
			err = api.CreateLoadBalancerBackends(backends)
			if err != nil {
				return fmt.Errorf("CNC CreateLoadBalancerBackends (retry after delete): %w", err)
			}
			m.log.Info("CNC CreateLoadBalancerBackends recreated",
				"backendID", id,
				"address", fmt.Sprintf("%s:%d", addr, port))
			return nil
		}
		return fmt.Errorf("CNC CreateLoadBalancerBackends: %w", err)
	}
	m.log.Info("CNC CreateLoadBalancerBackends succeeded",
		"backendID", id,
		"address", fmt.Sprintf("%s:%d", addr, port))

	return nil
}

// isAlreadyExistsError checks if the error is ERROR_ALREADY_EXISTS (HRESULT 0x800700B7).
func isAlreadyExistsError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "0x800700B7")
}

// DeleteBackend implements LBMaps.
func (m *CNCLBMaps) DeleteBackend(key BackendKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := uint32(key.GetID())
	delete(m.backends, id)

	api := m.api
	if api == nil {
		return nil
	}

	// Determine address family from key type (CNC uses AF_INET=2, AF_INET6=23)
	var af uint16
	switch key.(type) {
	case *Backend6KeyV3:
		af = 23
	default:
		af = 2
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

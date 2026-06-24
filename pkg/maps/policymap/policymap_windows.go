// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package policymap

import (
	"fmt"
	"sync"

	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/princepereira/cncshim/pkg/cncapi"
)

// CNCPolicyMap implements the PolicyMap interface using cncshim on Windows.
type CNCPolicyMap struct {
	mu      sync.RWMutex
	client  *winDatapath.CNCClient
	ifindex uint32
	name    string
	entries map[string]PolicyEntry
}

// NewCNCPolicyMap creates a Windows CNC-backed policy map for a given endpoint.
func NewCNCPolicyMap(client *winDatapath.CNCClient, ifindex uint32, name string) *CNCPolicyMap {
	return &CNCPolicyMap{
		client:  client,
		ifindex: ifindex,
		name:    name,
		entries: make(map[string]PolicyEntry),
	}
}

func cncPolicyKeyStr(key *PolicyKey) string {
	return fmt.Sprintf("%d:%d:%d:%d", key.Identity, key.DestPortNetwork, key.Nexthdr, key.TrafficDirection)
}

// Update implements PolicyMap.
func (m *CNCPolicyMap) Update(key *PolicyKey, entry *PolicyEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries[cncPolicyKeyStr(key)] = *entry

	api := m.client.API()
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}

	policy := cncapi.Policy{
		Key: cncapi.PolicyKey{
			Identity:        key.Identity,
			Protocol:        key.Nexthdr,
			Direction:       toCNCDirection(key.TrafficDirection),
			DestinationPort: key.GetDestPort(),
		},
		Value: cncapi.PolicyValue{
			ProxyPort:  entry.GetProxyPort(),
			Permission: toCNCPermission(entry),
		},
	}

	return api.AddOrUpdateEndpointPolicies(m.ifindex, []cncapi.Policy{policy})
}

// DeleteKey implements PolicyMap.
func (m *CNCPolicyMap) DeleteKey(key PolicyKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.entries, cncPolicyKeyStr(&key))

	api := m.client.API()
	if api == nil {
		return nil
	}

	cncKey := cncapi.PolicyKey{
		Identity:        key.Identity,
		Protocol:        key.Nexthdr,
		Direction:       toCNCDirection(key.TrafficDirection),
		DestinationPort: key.GetDestPort(),
	}

	return api.DeleteEndpointPolicies(m.ifindex, []cncapi.PolicyKey{cncKey})
}

// DeleteEntry implements PolicyMap.
func (m *CNCPolicyMap) DeleteEntry(entry *PolicyEntryDump) error {
	return m.DeleteKey(entry.Key)
}

// String implements PolicyMap.
func (m *CNCPolicyMap) String() string {
	return m.name
}

// Dump implements PolicyMap.
func (m *CNCPolicyMap) Dump() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return fmt.Sprintf("%d entries", len(m.entries)), nil
}

// DumpToSlice implements PolicyMap.
func (m *CNCPolicyMap) DumpToSlice() (PolicyEntriesDump, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return empty dump - entries tracked in-memory are simplified
	return PolicyEntriesDump{}, nil
}

// DumpToMapStateMap implements PolicyMap.
func (m *CNCPolicyMap) DumpToMapStateMap() (policyTypes.MapStateMap, error) {
	return nil, nil
}

// MaxEntries implements PolicyMap.
func (m *CNCPolicyMap) MaxEntries() uint32 {
	return 16384
}

// Close implements PolicyMap.
func (m *CNCPolicyMap) Close() error {
	return nil
}

func toCNCDirection(dir uint8) cncapi.Direction {
	if dir == 1 { // trafficdirection.Ingress
		return cncapi.DirectionIngress
	}
	return cncapi.DirectionEgress
}

func toCNCPermission(entry *PolicyEntry) cncapi.Permission {
	if entry.IsDeny() {
		return cncapi.PermissionDeny
	}
	return cncapi.PermissionAllow
}


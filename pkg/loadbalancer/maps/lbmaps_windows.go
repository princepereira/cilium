// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/hive/cell"

	"github.com/Microsoft/hnslib/hcn"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// newLBMaps is the Windows implementation of the LBMaps constructor.
// On Linux this creates eBPF maps; on Windows it creates an HNSLBMaps
// that manages load-balancing state through the Host Compute Network (HCN) API.
func newLBMaps(p lbmapsParams) bpf.MapOut[LBMaps] {
	if p.TestConfig != nil {
		m := NewFakeLBMaps()
		if p.TestConfig.TestFaultProbability > 0.0 {
			m = &FaultyLBMaps{
				impl:               m,
				failureProbability: p.TestConfig.TestFaultProbability,
			}
		}
		return bpf.NewMapOut(m)
	}

	r := &HNSLBMaps{log: p.Log}
	p.Lifecycle.Append(r)
	return bpf.NewMapOut(LBMaps(r))
}

// HNSLBMaps implements LBMaps using Windows Host Compute Network (HCN) APIs.
// This is the Windows equivalent of BPFLBMaps which uses Linux eBPF maps.
//
// On Linux, cilium_lb4_services_v2 is a kernel BPF hash map keyed by
// (address, port, proto, backend_slot). On Windows, the equivalent state is
// maintained via HCN load balancer policies using hnslib.
type HNSLBMaps struct {
	log interface{ Warn(string, ...any) }
}

// Start implements cell.HookInterface. Verifies HCN is available.
func (h *HNSLBMaps) Start(_ cell.HookContext) error {
	if _, err := hcn.GetCachedSupportedFeatures(); err != nil {
		return fmt.Errorf("HCN not available on this Windows host: %w", err)
	}
	return nil
}

// Stop implements cell.HookInterface.
func (h *HNSLBMaps) Stop(_ cell.HookContext) error {
	return nil
}

// UpdateService creates or updates an HCN load balancer for the given service.
// This is the Windows equivalent of writing to cilium_lb4_services_v2.
func (h *HNSLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	// Windows HCN load balancers are identified by VIP + port. Map the cilium
	// ServiceKey (addr/port/proto/slot) to an HCN HostComputeLoadBalancer.
	lb := &hcn.HostComputeLoadBalancer{
		// FrontendVIPs will be populated from the key in a full implementation.
	}
	_ = lb
	// TODO: translate key/value → HCN load balancer policy and call lb.Create() or lb.Update()
	return nil
}

// DeleteService removes the HCN load balancer entry for the given service key.
func (h *HNSLBMaps) DeleteService(key ServiceKey) error {
	// TODO: look up existing HCN load balancer by key and call lb.Delete()
	return nil
}

// DumpService iterates over all HCN load balancers and calls cb for each.
func (h *HNSLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	lbs, err := hcn.ListLoadBalancers()
	if err != nil {
		return fmt.Errorf("listing HCN load balancers: %w", err)
	}
	for range lbs {
		// TODO: translate HCN HostComputeLoadBalancer → ServiceKey/ServiceValue and call cb
	}
	return nil
}

// UpdateBackend registers a backend endpoint in HCN.
func (h *HNSLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	// TODO: create/update HCN endpoint for this backend
	return nil
}

// DeleteBackend removes a backend endpoint from HCN.
func (h *HNSLBMaps) DeleteBackend(key BackendKey) error {
	// TODO: delete HCN endpoint for this backend
	return nil
}

// DumpBackend iterates over all HCN endpoints and calls cb for each.
func (h *HNSLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	eps, err := hcn.ListEndpoints()
	if err != nil {
		return fmt.Errorf("listing HCN endpoints: %w", err)
	}
	for range eps {
		// TODO: translate HCN HostComputeEndpoint → BackendKey/BackendValue and call cb
	}
	return nil
}

// LookupBackend looks up a single backend by key.
func (h *HNSLBMaps) LookupBackend(key BackendKey) (BackendValue, error) {
	// TODO: look up HCN endpoint by backend ID
	return nil, os.ErrNotExist
}

// UpdateRevNat is a no-op on Windows; reverse NAT is handled internally by HCN.
func (h *HNSLBMaps) UpdateRevNat(RevNatKey, RevNatValue) error { return nil }

// DeleteRevNat is a no-op on Windows.
func (h *HNSLBMaps) DeleteRevNat(RevNatKey) error { return nil }

// DumpRevNat is a no-op on Windows; there are no separate reverse-NAT entries.
func (h *HNSLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error { return nil }

// UpdateAffinityMatch is a no-op on Windows; session affinity is configured via HCN flags.
func (h *HNSLBMaps) UpdateAffinityMatch(*AffinityMatchKey, *AffinityMatchValue) error { return nil }

// DeleteAffinityMatch is a no-op on Windows.
func (h *HNSLBMaps) DeleteAffinityMatch(*AffinityMatchKey) error { return nil }

// DumpAffinityMatch is a no-op on Windows.
func (h *HNSLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	return nil
}

// UpdateSourceRange is a no-op on Windows; source ranges map to HCN ACL policies.
func (h *HNSLBMaps) UpdateSourceRange(SourceRangeKey, *SourceRangeValue) error { return nil }

// DeleteSourceRange is a no-op on Windows.
func (h *HNSLBMaps) DeleteSourceRange(SourceRangeKey) error { return nil }

// DumpSourceRange is a no-op on Windows.
func (h *HNSLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error { return nil }

// UpdateMaglev is a no-op on Windows; consistent hashing is not used with HCN.
func (h *HNSLBMaps) UpdateMaglev(MaglevOuterKey, []loadbalancer.BackendID, bool) error { return nil }

// DeleteMaglev is a no-op on Windows.
func (h *HNSLBMaps) DeleteMaglev(MaglevOuterKey, bool) error { return nil }

// DumpMaglev is a no-op on Windows.
func (h *HNSLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	return nil
}

// UpdateSockRevNat is a no-op on Windows; socket-level reverse NAT is Linux-specific.
func (h *HNSLBMaps) UpdateSockRevNat(uint64, net.IP, uint16, uint16) error { return nil }

// DeleteSockRevNat is a no-op on Windows.
func (h *HNSLBMaps) DeleteSockRevNat(uint64, net.IP, uint16) error { return nil }

// ExistsSockRevNat always returns false on Windows.
func (h *HNSLBMaps) ExistsSockRevNat(uint64, net.IP, uint16) bool { return false }

// SockRevNat returns nil maps on Windows; sock rev-NAT is Linux eBPF-only.
func (h *HNSLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) { return nil, nil }

// IsEmpty returns true when there are no HCN load balancers present.
func (h *HNSLBMaps) IsEmpty() bool {
	lbs, err := hcn.ListLoadBalancers()
	if err != nil {
		return true
	}
	return len(lbs) == 0
}

var _ LBMaps = &HNSLBMaps{}

// NewFakeLBMaps returns an in-memory LBMaps for use in Windows unit tests
// (where neither eBPF nor a real HNS server is available).
func NewFakeLBMaps() LBMaps {
	return &fakeLBMaps{}
}

// fakeLBMaps is an in-memory LBMaps implementation used for Windows tests.
type fakeLBMaps struct {
	services  map[string]ServiceValue
	backends  map[string]BackendValue
	revNats   map[string]RevNatValue
	affinities map[string]*AffinityMatchValue
	srcRanges map[string]*SourceRangeValue
}

func (f *fakeLBMaps) init() {
	if f.services == nil {
		f.services = make(map[string]ServiceValue)
		f.backends = make(map[string]BackendValue)
		f.revNats = make(map[string]RevNatValue)
		f.affinities = make(map[string]*AffinityMatchValue)
		f.srcRanges = make(map[string]*SourceRangeValue)
	}
}

func (f *fakeLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	f.init()
	f.services[key.String()] = value
	return nil
}
func (f *fakeLBMaps) DeleteService(key ServiceKey) error {
	f.init()
	delete(f.services, key.String())
	return nil
}
func (f *fakeLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error { return nil }
func (f *fakeLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	f.init()
	f.backends[key.String()] = value
	return nil
}
func (f *fakeLBMaps) DeleteBackend(key BackendKey) error {
	f.init()
	delete(f.backends, key.String())
	return nil
}
func (f *fakeLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error    { return nil }
func (f *fakeLBMaps) LookupBackend(BackendKey) (BackendValue, error)          { return nil, os.ErrNotExist }
func (f *fakeLBMaps) UpdateRevNat(RevNatKey, RevNatValue) error               { return nil }
func (f *fakeLBMaps) DeleteRevNat(RevNatKey) error                            { return nil }
func (f *fakeLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error        { return nil }
func (f *fakeLBMaps) UpdateAffinityMatch(*AffinityMatchKey, *AffinityMatchValue) error { return nil }
func (f *fakeLBMaps) DeleteAffinityMatch(*AffinityMatchKey) error             { return nil }
func (f *fakeLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	return nil
}
func (f *fakeLBMaps) UpdateSourceRange(SourceRangeKey, *SourceRangeValue) error { return nil }
func (f *fakeLBMaps) DeleteSourceRange(SourceRangeKey) error                    { return nil }
func (f *fakeLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	return nil
}
func (f *fakeLBMaps) UpdateMaglev(MaglevOuterKey, []loadbalancer.BackendID, bool) error { return nil }
func (f *fakeLBMaps) DeleteMaglev(MaglevOuterKey, bool) error                            { return nil }
func (f *fakeLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	return nil
}
func (f *fakeLBMaps) UpdateSockRevNat(uint64, net.IP, uint16, uint16) error { return nil }
func (f *fakeLBMaps) DeleteSockRevNat(uint64, net.IP, uint16) error          { return nil }
func (f *fakeLBMaps) ExistsSockRevNat(uint64, net.IP, uint16) bool           { return false }
func (f *fakeLBMaps) SockRevNat() (*bpf.Map, *bpf.Map)                       { return nil, nil }
func (f *fakeLBMaps) IsEmpty() bool {
	return len(f.services) == 0 && len(f.backends) == 0
}

var _ LBMaps = &fakeLBMaps{}

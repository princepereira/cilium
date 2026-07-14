// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/princepereira/cncshim/pkg/cncapi"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
)

// Windows address families used by the CNC API.
const (
	windowsAFInet  uint16 = 2  // AF_INET
	windowsAFInet6 uint16 = 23 // AF_INET6
)

// hresultAlreadyExists is the HRESULT wrapping the Win32 ERROR_ALREADY_EXISTS
// (0x800700B7). The CNC "Create" APIs return it when the object already exists.
const hresultAlreadyExists cncapi.HResult = -2147024713 // 0x800700B7

// ignoreAlreadyExists swallows an ERROR_ALREADY_EXISTS HRESULT so that the CNC
// "Create" APIs behave as idempotent upserts, matching the semantics of the
// Linux BPF map updates the load-balancer reconciler expects.
func ignoreAlreadyExists(err error) error {
	var hrErr *cncapi.HResultError
	if errors.As(err, &hrErr) && hrErr.Code == hresultAlreadyExists {
		return nil
	}
	return err
}

// newLBMaps constructs the load-balancer "maps" implementation for Windows.
//
// On Windows there are no pinned eBPF maps managed directly by the agent.
// Instead the datapath is programmed through the CNC (Container Network
// Configuration) API exposed by cncapi.dll and wrapped by the cncshim module.
// Service/backend reconciliation is therefore translated into CNC calls while
// an in-memory bookkeeping store (FakeLBMaps) backs the Dump/Lookup operations
// that the reconciler relies on to compute differences.
func newLBMaps(p lbmapsParams) bpf.MapOut[LBMaps] {
	if p.TestConfig != nil {
		// Under test, use the in-memory fake (optionally faulty) without
		// touching the CNC datapath.
		var m LBMaps = NewFakeLBMaps()
		if p.TestConfig.TestFaultProbability > 0.0 {
			m = &FaultyLBMaps{
				impl:               m,
				failureProbability: p.TestConfig.TestFaultProbability,
			}
		}
		return bpf.NewMapOut(m)
	}

	r := &CNCLBMaps{
		FakeLBMaps: &FakeLBMaps{},
		Log:        p.Log,
		Cfg:        p.Config,
		ExtCfg:     p.ExtConfig,
	}
	p.Lifecycle.Append(r)
	return bpf.NewMapOut(LBMaps(r))
}

// CNCLBMaps implements [LBMaps] on Windows by programming the CNC datapath via
// the cncshim API. It embeds [FakeLBMaps] to provide the in-memory bookkeeping
// used by Dump/Lookup/IsEmpty, and overrides the service/backend write paths to
// additionally push the configuration into the kernel through cncapi.dll.
type CNCLBMaps struct {
	// FakeLBMaps provides the in-memory bookkeeping store. Its methods are
	// promoted and used for all read-back operations; the write methods below
	// shadow the promoted ones to also program the CNC datapath.
	*FakeLBMaps

	Log    *slog.Logger
	Cfg    loadbalancer.Config
	ExtCfg loadbalancer.ExternalConfig

	// client is the CNC API client backed by cncapi.dll. It is created in
	// Start and released in Stop. It may be nil if initialization failed.
	client cncapi.CNCApi

	// serviceIDs maps a frontend (addr/port/proto) to the CNC service ID
	// (the Cilium RevNat ID) so a service can be deleted by ID later.
	serviceIDs lock.Map[string, uint16]
}

var (
	_ LBMaps             = &CNCLBMaps{}
	_ cell.HookInterface = &CNCLBMaps{}
)

// Start implements cell.HookInterface. It initializes the CNC client.
func (c *CNCLBMaps) Start(cell.HookContext) error {
	c.Log.Info("Initializing CNC load-balancer datapath",
		"cncshim", cncapi.GetVersion(),
		"cncApi", cncapi.GetCNCApiVersion(),
	)
	client, err := cncapi.New()
	if err != nil {
		return fmt.Errorf("initializing CNC API client: %w", err)
	}
	c.client = client
	return nil
}

// Stop implements cell.HookInterface. It releases the CNC client.
func (c *CNCLBMaps) Stop(cell.HookContext) error {
	if c.client == nil {
		return nil
	}
	err := c.client.Close()
	c.client = nil
	return err
}

func frontendID(key ServiceKey) string {
	return fmt.Sprintf("%s/%d/%d", key.GetAddress(), key.GetPort(), key.GetProtocol())
}

func frontendInfo(key ServiceKey) cncapi.FrontendInfo {
	return cncapi.FrontendInfo{
		IPAddress: key.GetAddress(),
		Port:      key.GetPort(),
		Protocol:  key.GetProtocol(),
	}
}

// isWildcardService reports whether the service key is the port-0 / proto-ANY
// wildcard master entry that the load-balancer reconciler programs for the BPF
// datapath (a catch-all so any-port traffic to a LB/ClusterIP address matches a
// service entry). The CNC datapath has no notion of such catch-all entries and
// rejects them with E_INVALIDARG, so they are kept only in the in-memory
// bookkeeping and never pushed through cncapi.dll.
func isWildcardService(key ServiceKey) bool {
	return key.GetPort() == 0 && key.GetProtocol() == 0
}

func backendInfo(key BackendKey, value BackendValue) cncapi.BackendInfo {
	return cncapi.BackendInfo{
		BackendID: uint32(key.GetID()),
		IPAddress: value.GetAddress().Addr(),
		Port:      value.GetPort(),
	}
}

// UpdateService implements [serviceMaps]. The master slot (slot 0) carries the
// frontend definition and is programmed into the CNC datapath; per-backend
// slots only update the in-memory bookkeeping (backend membership is programmed
// through UpdateBackend / the CNC backend APIs).
func (c *CNCLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	if c.client != nil && key.GetBackendSlot() == 0 && !isWildcardService(key) {
		serviceID := uint16(value.GetRevNat())
		info := &cncapi.LoadBalancerInfo{
			ServiceType:  cncapi.ServiceTypeClusterIP,
			Frontend:     frontendInfo(key),
			ServiceFlags: cncapi.ServiceFlags(value.GetFlags()),
		}
		if err := c.client.CreateLoadBalancerService(serviceID, info); err != nil {
			if err := ignoreAlreadyExists(err); err != nil {
				return fmt.Errorf("CncCreateLoadBalancerService: %w", err)
			}
		}
		c.serviceIDs.Store(frontendID(key), serviceID)
	}
	return c.FakeLBMaps.UpdateService(key, value)
}

// DeleteService implements [serviceMaps].
func (c *CNCLBMaps) DeleteService(key ServiceKey) error {
	if c.client != nil && key.GetBackendSlot() == 0 && !isWildcardService(key) {
		if serviceID, ok := c.serviceIDs.Load(frontendID(key)); ok {
			info := &cncapi.LoadBalancerInfo{
				ServiceType: cncapi.ServiceTypeClusterIP,
				Frontend:    frontendInfo(key),
			}
			if err := c.client.DeleteLoadBalancerService(serviceID, info); err != nil {
				return fmt.Errorf("CncDeleteLoadBalancerService: %w", err)
			}
			c.serviceIDs.Delete(frontendID(key))
		}
	}
	return c.FakeLBMaps.DeleteService(key)
}

// UpdateBackend implements [backendMaps]. It registers the backend with the CNC
// datapath and records it in the in-memory store.
func (c *CNCLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	if c.client != nil {
		be := backendInfo(key, value)
		if err := c.client.CreateLoadBalancerBackends([]cncapi.BackendInfo{be}); err != nil {
			if err := ignoreAlreadyExists(err); err != nil {
				return fmt.Errorf("CncCreateLoadBalancerBackends: %w", err)
			}
		}
	}
	return c.FakeLBMaps.UpdateBackend(key, value)
}

// DeleteBackend implements [backendMaps].
func (c *CNCLBMaps) DeleteBackend(key BackendKey) error {
	if c.client != nil {
		af := windowsAFInet
		if value, err := c.FakeLBMaps.LookupBackend(key); err == nil {
			if value.GetAddress().Addr().Is6() {
				af = windowsAFInet6
			}
		}
		if err := c.client.DeleteLoadBalancerBackends(af, []uint32{uint32(key.GetID())}); err != nil {
			return fmt.Errorf("CncDeleteLoadBalancerBackends: %w", err)
		}
	}
	return c.FakeLBMaps.DeleteBackend(key)
}

// DumpService implements [serviceMaps]. Served from the in-memory bookkeeping
// store; the reconciler uses this to compute the desired-vs-actual difference.
func (c *CNCLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	return c.FakeLBMaps.DumpService(cb)
}

// DumpBackend implements [backendMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	return c.FakeLBMaps.DumpBackend(cb)
}

// LookupBackend implements [backendMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) LookupBackend(key BackendKey) (BackendValue, error) {
	return c.FakeLBMaps.LookupBackend(key)
}

//
// Reverse NAT.
//
// The CNC datapath derives reverse-NAT state from the load-balancer service and
// backend configuration, so there is no dedicated CNC API for it. The entries
// are tracked in-memory to keep the reconciler's view consistent.
//

// UpdateRevNat implements [revNatMaps].
func (c *CNCLBMaps) UpdateRevNat(key RevNatKey, value RevNatValue) error {
	c.Log.Debug("UpdateRevNat not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.UpdateRevNat(key, value)
}

// DeleteRevNat implements [revNatMaps].
func (c *CNCLBMaps) DeleteRevNat(key RevNatKey) error {
	c.Log.Debug("DeleteRevNat not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.DeleteRevNat(key)
}

// DumpRevNat implements [revNatMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error {
	return c.FakeLBMaps.DumpRevNat(cb)
}

//
// Session affinity.
//
// Affinity is configured per-service through LoadBalancerInfo.AffinityTimeoutSeconds
// rather than via a dedicated affinity-match map, so there is no standalone CNC
// API. Entries are tracked in-memory.
//

// UpdateAffinityMatch implements [affinityMaps].
func (c *CNCLBMaps) UpdateAffinityMatch(key *AffinityMatchKey, value *AffinityMatchValue) error {
	c.Log.Debug("UpdateAffinityMatch not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.UpdateAffinityMatch(key, value)
}

// DeleteAffinityMatch implements [affinityMaps].
func (c *CNCLBMaps) DeleteAffinityMatch(key *AffinityMatchKey) error {
	c.Log.Debug("DeleteAffinityMatch not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.DeleteAffinityMatch(key)
}

// DumpAffinityMatch implements [affinityMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	return c.FakeLBMaps.DumpAffinityMatch(cb)
}

//
// Source ranges (loadBalancerSourceRanges).
//
// Not exposed as a dedicated CNC API. Entries are tracked in-memory.
//

// UpdateSourceRange implements [sourceRangeMaps].
func (c *CNCLBMaps) UpdateSourceRange(key SourceRangeKey, value *SourceRangeValue) error {
	c.Log.Debug("UpdateSourceRange not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.UpdateSourceRange(key, value)
}

// DeleteSourceRange implements [sourceRangeMaps].
func (c *CNCLBMaps) DeleteSourceRange(key SourceRangeKey) error {
	c.Log.Debug("DeleteSourceRange not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.DeleteSourceRange(key)
}

// DumpSourceRange implements [sourceRangeMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	return c.FakeLBMaps.DumpSourceRange(cb)
}

//
// Maglev backend tables.
//
// The CNC datapath selects its own load-balancing algorithm and does not expose
// the Maglev lookup tables, so there is no corresponding CNC API. Entries are
// tracked in-memory.
//

// UpdateMaglev implements [maglevMaps].
func (c *CNCLBMaps) UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	c.Log.Debug("UpdateMaglev not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.UpdateMaglev(key, backendIDs, ipv6)
}

// DeleteMaglev implements [maglevMaps].
func (c *CNCLBMaps) DeleteMaglev(key MaglevOuterKey, ipv6 bool) error {
	c.Log.Debug("DeleteMaglev not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.DeleteMaglev(key, ipv6)
}

// DumpMaglev implements [maglevMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	return c.FakeLBMaps.DumpMaglev(cb)
}

//
// Socket reverse NAT (used by the socket-LB / connect-time load balancer).
//
// The CNC datapath manages socket reverse-NAT internally and exposes no API for
// it, so these operations are tracked in-memory only.
//

// UpdateSockRevNat implements [sockRevNatMaps].
func (c *CNCLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	c.Log.Debug("UpdateSockRevNat not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.UpdateSockRevNat(cookie, addr, port, revNatIndex)
}

// DeleteSockRevNat implements [sockRevNatMaps].
func (c *CNCLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	c.Log.Debug("DeleteSockRevNat not implemented in the CNC datapath; tracking in-memory only")
	return c.FakeLBMaps.DeleteSockRevNat(cookie, addr, port)
}

// ExistsSockRevNat implements [sockRevNatMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	return c.FakeLBMaps.ExistsSockRevNat(cookie, addr, port)
}

// SockRevNat implements [sockRevNatMaps]. There are no pinned BPF maps on Windows.
func (c *CNCLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) {
	return nil, nil
}

// IsEmpty implements [LBMaps]. Served from the in-memory bookkeeping store.
func (c *CNCLBMaps) IsEmpty() bool {
	return c.FakeLBMaps.IsEmpty()
}

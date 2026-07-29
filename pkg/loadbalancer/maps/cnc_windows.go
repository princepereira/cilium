// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"net/netip"
	"sync"

	"github.com/princepereira/cncshim/pkg/cncapi"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cnc"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// Windows address-family values (winsock2 AF_INET / AF_INET6), matching the
// values cncshim's ABI layer uses internally.
const (
	afInet  uint16 = 2
	afInet6 uint16 = 23
)

// init wires the load-balancer BPF maps into the native Windows CNC datapath.
//
// Cilium writes services and backends into its typed BPF maps as raw slot
// entries: a service "master" entry (backend slot 0) carrying the service ID,
// flags and backend count, one service "slot" entry per backend (slot 1..N)
// referencing a backend ID, and a global backend table keyed by backend ID.
// cncshim, in contrast, is semantic: it wants a service frontend plus the set
// of backends associated with it. The translator below bridges the two: it
// accumulates the raw writes into per-service state and emits the equivalent
// CreateLoadBalancerService / UpdateLoadBalancerServiceBackends /
// DeleteLoadBalancer* calls.
//
// Backends and service slots may be written in either order; the translator is
// order-independent because it re-reconciles a service whenever a backend it
// references appears or disappears.
func init() {
	t := newLBTranslator()
	bpf.RegisterMapSyncHook(Service4MapV2Name, t.serviceHook)
	bpf.RegisterMapSyncHook(Service6MapV2Name, t.serviceHook)
	bpf.RegisterMapSyncHook(Backend4MapV3Name, t.backendHookFor(afInet))
	bpf.RegisterMapSyncHook(Backend6MapV3Name, t.backendHookFor(afInet6))
}

// frontendKey identifies a service frontend across its master and slot entries.
type frontendKey struct {
	addr  netip.Addr
	port  uint16
	proto uint8
	scope uint8
}

// svcState holds the accumulated state for a single service frontend.
type svcState struct {
	serviceID uint16
	af        uint16
	info      *cncapi.LoadBalancerInfo
	created   bool
	// slots maps backend slot index (>0) to backend ID.
	slots map[int]uint32
	// applied is the set of backend IDs currently associated with the
	// service in the CNC datapath.
	applied map[uint32]struct{}
}

// backendEntry is a globally-registered backend plus its address family.
type backendEntry struct {
	info cncapi.BackendInfo
	af   uint16
}

// lbTranslator converts Cilium's raw LB map writes into cncshim's semantic
// service/backend API. All state is guarded by mu.
type lbTranslator struct {
	mu       sync.Mutex
	services map[frontendKey]*svcState
	backends map[uint32]backendEntry
}

func newLBTranslator() *lbTranslator {
	return &lbTranslator{
		services: map[frontendKey]*svcState{},
		backends: map[uint32]backendEntry{},
	}
}

func afOf(addr netip.Addr) uint16 {
	if addr.Is6() && !addr.Is4In6() {
		return afInet6
	}
	return afInet
}

// serviceHook mirrors a services-map write. Slot 0 is the master entry (service
// metadata); slots >0 reference individual backends.
func (t *lbTranslator) serviceHook(op bpf.MapOp, key bpf.MapKey, value bpf.MapValue) error {
	sk, ok := key.(ServiceKey)
	if !ok {
		return nil
	}
	sk = sk.ToHost()
	fk := frontendKey{
		addr:  sk.GetAddress(),
		port:  sk.GetPort(),
		proto: sk.GetProtocol(),
		scope: sk.GetScope(),
	}
	slot := sk.GetBackendSlot()

	t.mu.Lock()
	defer t.mu.Unlock()

	switch op {
	case bpf.MapOpUpdate:
		sv, ok := value.(ServiceValue)
		if !ok {
			return nil
		}
		sv = sv.ToHost()
		if slot == 0 {
			return t.updateMaster(fk, sk, sv)
		}
		return t.updateSlot(fk, slot, uint32(sv.GetBackendID()))
	case bpf.MapOpDelete:
		if slot == 0 {
			return t.deleteMaster(fk)
		}
		return t.deleteSlot(fk, slot)
	}
	return nil
}

// backendHookFor returns a hook for the backend map of the given address family.
func (t *lbTranslator) backendHookFor(af uint16) bpf.MapSyncHook {
	return func(op bpf.MapOp, key bpf.MapKey, value bpf.MapValue) error {
		bk, ok := key.(BackendKey)
		if !ok {
			return nil
		}
		id := uint32(bk.GetID())

		t.mu.Lock()
		defer t.mu.Unlock()

		switch op {
		case bpf.MapOpUpdate:
			bv, ok := value.(BackendValue)
			if !ok {
				return nil
			}
			bv = bv.ToHost()
			return t.updateBackend(id, af, bv)
		case bpf.MapOpDelete:
			return t.deleteBackend(id, af)
		}
		return nil
	}
}

func (t *lbTranslator) getOrCreateService(fk frontendKey) *svcState {
	st := t.services[fk]
	if st == nil {
		st = &svcState{
			slots:   map[int]uint32{},
			applied: map[uint32]struct{}{},
		}
		t.services[fk] = st
	}
	return st
}

func (t *lbTranslator) updateMaster(fk frontendKey, sk ServiceKey, sv ServiceValue) error {
	st := t.getOrCreateService(fk)
	st.serviceID = uint16(sv.GetRevNat())
	st.af = afOf(sk.GetAddress())
	st.info = buildLBInfo(fk, sv)
	if err := cnc.CreateLoadBalancerService(st.serviceID, st.info); err != nil {
		return err
	}
	st.created = true
	return t.reconcile(st)
}

func (t *lbTranslator) updateSlot(fk frontendKey, slot int, backendID uint32) error {
	st := t.getOrCreateService(fk)
	st.slots[slot] = backendID
	return t.reconcile(st)
}

func (t *lbTranslator) deleteMaster(fk frontendKey) error {
	st := t.services[fk]
	if st == nil {
		return nil
	}
	delete(t.services, fk)
	if st.created && st.info != nil {
		return cnc.DeleteLoadBalancerService(st.serviceID, st.info)
	}
	return nil
}

func (t *lbTranslator) deleteSlot(fk frontendKey, slot int) error {
	st := t.services[fk]
	if st == nil {
		return nil
	}
	delete(st.slots, slot)
	return t.reconcile(st)
}

func (t *lbTranslator) updateBackend(id uint32, af uint16, bv BackendValue) error {
	info := cncapi.BackendInfo{
		BackendID: id,
		IPAddress: bv.GetAddress().Addr(),
		Port:      bv.GetPort(),
	}
	t.backends[id] = backendEntry{info: info, af: af}
	if err := cnc.CreateLoadBalancerBackends([]cncapi.BackendInfo{info}); err != nil {
		return err
	}
	// A service slot may already reference this backend (backend written
	// after the slot); re-reconcile so the association is applied.
	for _, st := range t.services {
		if st.references(id) {
			if err := t.reconcile(st); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *lbTranslator) deleteBackend(id uint32, af uint16) error {
	if _, ok := t.backends[id]; !ok {
		return nil
	}
	delete(t.backends, id)
	// Disassociate this backend from any service that still references it.
	for _, st := range t.services {
		if st.references(id) {
			if err := t.reconcile(st); err != nil {
				return err
			}
		}
	}
	return cnc.DeleteLoadBalancerBackends(af, []uint32{id})
}

func (st *svcState) references(id uint32) bool {
	for _, bid := range st.slots {
		if bid == id {
			return true
		}
	}
	return false
}

// reconcile computes the desired backend set for a service (the union of its
// slot references that have a known global backend) and issues the delta to
// cncshim. It is a no-op until the master entry has been seen.
func (t *lbTranslator) reconcile(st *svcState) error {
	if !st.created || st.info == nil {
		return nil
	}
	desired := map[uint32]cncapi.BackendInfo{}
	for _, id := range st.slots {
		if be, ok := t.backends[id]; ok {
			desired[id] = be.info
		}
	}

	var toAdd, toRemove []cncapi.BackendInfo
	for id, info := range desired {
		if _, ok := st.applied[id]; !ok {
			toAdd = append(toAdd, info)
		}
	}
	for id := range st.applied {
		if _, ok := desired[id]; !ok {
			// Reconstruct minimal BackendInfo for removal (ID is what
			// cncshim needs to dissociate).
			toRemove = append(toRemove, cncapi.BackendInfo{BackendID: id})
		}
	}

	if len(toAdd) == 0 && len(toRemove) == 0 {
		return nil
	}
	if err := cnc.UpdateLoadBalancerServiceBackends(st.serviceID, st.info, toAdd, toRemove); err != nil {
		return err
	}
	st.applied = map[uint32]struct{}{}
	for id := range desired {
		st.applied[id] = struct{}{}
	}
	return nil
}

// buildLBInfo translates a Cilium service master entry into cncshim's
// LoadBalancerInfo (service type, frontend tuple, traffic-policy and session
// affinity flags).
func buildLBInfo(fk frontendKey, sv ServiceValue) *cncapi.LoadBalancerInfo {
	flags := loadbalancer.ServiceFlags(sv.GetFlags())

	var st cncapi.ServiceType
	switch flags.SVCType() {
	case loadbalancer.SVCTypeNodePort:
		st = cncapi.ServiceTypeNodePort
	case loadbalancer.SVCTypeLoadBalancer:
		st = cncapi.ServiceTypeLoadBalancer
	case loadbalancer.SVCTypeHostPort:
		st = cncapi.ServiceTypeHostPort
	default:
		st = cncapi.ServiceTypeClusterIP
	}

	var sf cncapi.ServiceFlags
	if flags.SVCExtTrafficPolicy() == loadbalancer.SVCTrafficPolicyLocal {
		sf |= cncapi.ServiceFlagExternalTrafficPolicyLocal
	}
	if flags.SVCIntTrafficPolicy() == loadbalancer.SVCTrafficPolicyLocal {
		sf |= cncapi.ServiceFlagInternalTrafficPolicyLocal
	}

	info := &cncapi.LoadBalancerInfo{
		ServiceType: st,
		Frontend: cncapi.FrontendInfo{
			IPAddress: fk.addr,
			Port:      fk.port,
			Protocol:  fk.proto,
		},
		ServiceFlags: sf,
	}
	if to := sv.GetSessionAffinityTimeoutSec(); to > 0 {
		info.AffinityTimeoutSeconds = to
		info.ServiceFlags |= cncapi.ServiceFlagSessionAffinity
	}
	return info
}

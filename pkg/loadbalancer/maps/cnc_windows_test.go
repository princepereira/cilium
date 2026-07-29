// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"net"
	"net/netip"
	"testing"

	"github.com/princepereira/cncshim/pkg/cncapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cnc"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/u8proto"
)

// recordingMock captures the LB calls the translator makes so the test can
// assert on the semantic output.
type recordingMock struct {
	cncapi.MockClient
	createdServices map[uint16]*cncapi.LoadBalancerInfo
	createdBackends map[uint32]cncapi.BackendInfo
	deletedServices map[uint16]bool
	deletedBackends map[uint32]bool
	// assoc[serviceID] is the set of backend IDs currently associated.
	assoc map[uint16]map[uint32]struct{}
}

func newRecordingMock() *recordingMock {
	m := &recordingMock{
		createdServices: map[uint16]*cncapi.LoadBalancerInfo{},
		createdBackends: map[uint32]cncapi.BackendInfo{},
		deletedServices: map[uint16]bool{},
		deletedBackends: map[uint32]bool{},
		assoc:           map[uint16]map[uint32]struct{}{},
	}
	m.CreateLoadBalancerBackendsFn = func(backends []cncapi.BackendInfo) error {
		for _, b := range backends {
			m.createdBackends[b.BackendID] = b
		}
		return nil
	}
	m.CreateLoadBalancerServiceFn = func(serviceID uint16, info *cncapi.LoadBalancerInfo) error {
		m.createdServices[serviceID] = info
		if m.assoc[serviceID] == nil {
			m.assoc[serviceID] = map[uint32]struct{}{}
		}
		return nil
	}
	m.UpdateLoadBalancerServiceBackendsFn = func(serviceID uint16, info *cncapi.LoadBalancerInfo, newBackends, oldBackends []cncapi.BackendInfo) error {
		if m.assoc[serviceID] == nil {
			m.assoc[serviceID] = map[uint32]struct{}{}
		}
		for _, b := range newBackends {
			m.assoc[serviceID][b.BackendID] = struct{}{}
		}
		for _, b := range oldBackends {
			delete(m.assoc[serviceID], b.BackendID)
		}
		return nil
	}
	m.DeleteLoadBalancerServiceFn = func(serviceID uint16, info *cncapi.LoadBalancerInfo) error {
		m.deletedServices[serviceID] = true
		delete(m.assoc, serviceID)
		return nil
	}
	m.DeleteLoadBalancerBackendsFn = func(addressFamily uint16, backendIDs []uint32) error {
		for _, id := range backendIDs {
			m.deletedBackends[id] = true
		}
		return nil
	}
	return m
}

func svcKey(t *testing.T, ip string, port uint16, slot uint16) ServiceKey {
	return NewService4Key(net.ParseIP(ip), port, u8proto.TCP, loadbalancer.ScopeExternal, slot).ToNetwork()
}

func masterVal(serviceID uint16) ServiceValue {
	return (&Service4Value{RevNat: serviceID}).ToNetwork()
}

func slotVal(backendID uint32) ServiceValue {
	return (&Service4Value{BackendID: backendID}).ToNetwork()
}

func backendKV(t *testing.T, id uint32, ip string, port uint16) (BackendKey, BackendValue) {
	ac := cmtypes.AddrClusterFrom(netip.MustParseAddr(ip), 0)
	v, err := NewBackend4ValueV3(ac, port, u8proto.TCP, loadbalancer.BackendStateActive, 0)
	require.NoError(t, err)
	return NewBackend4KeyV3(loadbalancer.BackendID(id)), v.ToNetwork()
}

func TestLBTranslator_ServiceAndBackends(t *testing.T) {
	mock := newRecordingMock()
	cnc.SetClientForTesting(mock)
	t.Cleanup(func() { cnc.SetClientForTesting(nil) })

	tr := newLBTranslator()
	backendHook := tr.backendHookFor(afInet)

	const (
		vip       = "10.0.0.1"
		serviceID = uint16(7)
	)

	// 1. Backend written before the service slot (order-independence).
	bk, bv := backendKV(t, 100, "10.244.0.5", 8080)
	require.NoError(t, backendHook(bpf.MapOpUpdate, bk, bv))
	assert.Contains(t, mock.createdBackends, uint32(100))

	// 2. Service master entry (slot 0) carries the service ID.
	require.NoError(t, tr.serviceHook(bpf.MapOpUpdate, svcKey(t, vip, 80, 0), masterVal(serviceID)))
	require.Contains(t, mock.createdServices, serviceID)
	info := mock.createdServices[serviceID]
	assert.Equal(t, cncapi.ServiceTypeClusterIP, info.ServiceType)
	assert.Equal(t, netip.MustParseAddr(vip), info.Frontend.IPAddress)
	assert.Equal(t, uint16(80), info.Frontend.Port)

	// 3. Service slot 1 references backend 100 -> association applied.
	require.NoError(t, tr.serviceHook(bpf.MapOpUpdate, svcKey(t, vip, 80, 1), slotVal(100)))
	require.Contains(t, mock.assoc, serviceID)
	assert.Contains(t, mock.assoc[serviceID], uint32(100))

	// 4. Add a second backend AFTER its slot (backend arrives late).
	require.NoError(t, tr.serviceHook(bpf.MapOpUpdate, svcKey(t, vip, 80, 2), slotVal(200)))
	assert.NotContains(t, mock.assoc[serviceID], uint32(200), "unknown backend must not be associated yet")
	bk2, bv2 := backendKV(t, 200, "10.244.0.6", 8080)
	require.NoError(t, backendHook(bpf.MapOpUpdate, bk2, bv2))
	assert.Contains(t, mock.assoc[serviceID], uint32(200), "backend must be associated once it appears")

	// 5. Remove slot 1 -> backend 100 dissociated.
	require.NoError(t, tr.serviceHook(bpf.MapOpDelete, svcKey(t, vip, 80, 1), nil))
	assert.NotContains(t, mock.assoc[serviceID], uint32(100))
	assert.Contains(t, mock.assoc[serviceID], uint32(200))

	// 6. Delete the backend from the global table.
	require.NoError(t, backendHook(bpf.MapOpDelete, bk2, nil))
	assert.True(t, mock.deletedBackends[200])

	// 7. Delete the master entry -> service removed.
	require.NoError(t, tr.serviceHook(bpf.MapOpDelete, svcKey(t, vip, 80, 0), nil))
	assert.True(t, mock.deletedServices[serviceID])
}

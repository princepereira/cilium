// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package datapath

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/maps/authmap"
	fakeauthmap "github.com/cilium/cilium/pkg/maps/authmap/fake"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	fakeencrypt "github.com/cilium/cilium/pkg/maps/encrypt/fake"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	fakesignalmap "github.com/cilium/cilium/pkg/maps/signalmap/fake"
	"github.com/cilium/cilium/pkg/time"
)

// On Linux these BPF maps are provided by pkg/maps cells. Those maps live in
// the kernel and do not exist on non-Linux platforms, so we provide fake or nil
// implementations. Consumers that only observe these maps (auth manager, status
// collector, ...) can then be constructed and started; datapath operations that
// would program the maps are effectively no-ops.
type mapStubsOut struct {
	cell.Out

	SignalMap  signalmap.Map
	AuthMap    authmap.Map
	EncryptMap encrypt.EncryptMap

	EgressPolicyMap4 *egressmap.PolicyMap4
	EgressPolicyMap6 *egressmap.PolicyMap6

	NatMap4 nat.NatMap4
	NatMap6 nat.NatMap6
}

func newMapStubs() mapStubsOut {
	return mapStubsOut{
		SignalMap:        fakesignalmap.NewFakeSignalMap([][]byte{}, time.Second),
		AuthMap:          fakeauthmap.NewFakeAuthMap(),
		EncryptMap:       fakeencrypt.NewFakeEncryptMap(),
		EgressPolicyMap4: nil,
		EgressPolicyMap6: nil,
		NatMap4:          nil,
		NatMap6:          nil,
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maglev"
)

type lbmapsParams struct {
	cell.In

	Log          *slog.Logger
	Lifecycle    cell.Lifecycle
	TestConfig   *loadbalancer.TestConfig `optional:"true"`
	MaglevConfig maglev.Config
	Config       loadbalancer.Config
	ExtConfig    loadbalancer.ExternalConfig
}

type serviceMaps interface {
	UpdateService(key ServiceKey, value ServiceValue) error
	DeleteService(key ServiceKey) error
	DumpService(cb func(ServiceKey, ServiceValue)) error
}

type backendMaps interface {
	UpdateBackend(BackendKey, BackendValue) error
	DeleteBackend(BackendKey) error
	DumpBackend(cb func(BackendKey, BackendValue)) error
	LookupBackend(BackendKey) (BackendValue, error)
}

type revNatMaps interface {
	UpdateRevNat(RevNatKey, RevNatValue) error
	DeleteRevNat(RevNatKey) error
	DumpRevNat(cb func(RevNatKey, RevNatValue)) error
}

type affinityMaps interface {
	UpdateAffinityMatch(*AffinityMatchKey, *AffinityMatchValue) error
	DeleteAffinityMatch(*AffinityMatchKey) error
	DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error
}

type sourceRangeMaps interface {
	UpdateSourceRange(SourceRangeKey, *SourceRangeValue) error
	DeleteSourceRange(SourceRangeKey) error
	DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error
}

type maglevMaps interface {
	UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error
	DeleteMaglev(key MaglevOuterKey, ipv6 bool) error
	DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error
}

type sockRevNatMaps interface {
	UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error
	DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error
	ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool
	SockRevNat() (*bpf.Map, *bpf.Map)
}

// LBMaps defines the map operations performed by the reconciliation.
// Depending on this interface instead of on the underlying maps allows
// testing the implementation with a fake map or injected errors.
type LBMaps interface {
	serviceMaps
	backendMaps
	revNatMaps
	affinityMaps
	sourceRangeMaps
	maglevMaps
	sockRevNatMaps

	IsEmpty() bool
}

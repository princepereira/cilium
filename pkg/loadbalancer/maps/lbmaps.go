// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/u8proto"
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

// FaultyLBMaps wraps an LBMaps implementation and randomly fails operations
// with a configurable probability. Used for fault-injection testing.
type FaultyLBMaps struct {
	impl LBMaps

	// 0.0 (never fail) ... 1.0 (always fail)
	failureProbability float32
}

// DeleteSockRevNat implements LBMaps.
func (f *FaultyLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteSockRevNat(cookie, addr, port)
}

// UpdateSockRevNat implements LBMaps.
func (f *FaultyLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateSockRevNat(cookie, addr, port, revNatIndex)
}

// DeleteSourceRange implements lbmaps.
func (f *FaultyLBMaps) DeleteSourceRange(key SourceRangeKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteSourceRange(key)
}

// DumpSourceRange implements lbmaps.
func (f *FaultyLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DumpSourceRange(cb)
}

// UpdateSourceRange implements lbmaps.
func (f *FaultyLBMaps) UpdateSourceRange(key SourceRangeKey, value *SourceRangeValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateSourceRange(key, value)
}

// DeleteAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) DeleteAffinityMatch(key *AffinityMatchKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteAffinityMatch(key)
}

// DumpAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	return f.impl.DumpAffinityMatch(cb)
}

// UpdateAffinityMatch implements lbmaps.
func (f *FaultyLBMaps) UpdateAffinityMatch(key *AffinityMatchKey, value *AffinityMatchValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateAffinityMatch(key, value)
}

// DeleteRevNat implements lbmaps.
func (f *FaultyLBMaps) DeleteRevNat(key RevNatKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteRevNat(key)
}

// DumpRevNat implements lbmaps.
func (f *FaultyLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DumpRevNat(cb)
}

// UpdateRevNat implements lbmaps.
func (f *FaultyLBMaps) UpdateRevNat(key RevNatKey, value RevNatValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateRevNat(key, value)
}

// DeleteBackend implements lbmaps.
func (f *FaultyLBMaps) DeleteBackend(key BackendKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteBackend(key)
}

// DeleteService implements lbmaps.
func (f *FaultyLBMaps) DeleteService(key ServiceKey) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteService(key)
}

// DumpBackend implements lbmaps.
func (f *FaultyLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	return f.impl.DumpBackend(cb)
}

// DumpService implements lbmaps.
func (f *FaultyLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	return f.impl.DumpService(cb)
}

// IsEmpty implements lbmaps.
func (f *FaultyLBMaps) IsEmpty() bool {
	return f.impl.IsEmpty()
}

// UpdateBackend implements lbmaps.
func (f *FaultyLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateBackend(key, value)
}

// UpdateService implements lbmaps.
func (f *FaultyLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateService(key, value)
}

// UpdateMaglev implements lbmaps.
func (f *FaultyLBMaps) UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.UpdateMaglev(key, backendIDs, ipv6)
}

// DeleteMaglev implements lbmaps.
func (f *FaultyLBMaps) DeleteMaglev(key MaglevOuterKey, ipv6 bool) error {
	if f.isFaulty() {
		return errFaulty
	}
	return f.impl.DeleteMaglev(key, ipv6)
}

// DumpMaglev implements lbmaps.
func (f *FaultyLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	return f.impl.DumpMaglev(cb)
}

func (f *FaultyLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	return f.impl.ExistsSockRevNat(cookie, addr, port)
}

func (f *FaultyLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) {
	return f.impl.SockRevNat()
}

// LookupBackend implements LBMaps.
func (f *FaultyLBMaps) LookupBackend(key BackendKey) (BackendValue, error) {
	return f.impl.LookupBackend(key)
}

func (f *FaultyLBMaps) isFaulty() bool {
	// Float32() returns value between [0.0, 1.0).
	// We fail if the value is less than our probability [0.0, 1.0].
	return f.failureProbability > rand.Float32()
}

var errFaulty = errors.New("faulty")

var _ LBMaps = &FaultyLBMaps{}

// mapKeyValue stores a snapshot of a single BPF map entry.
type mapKeyValue struct {
	key   bpf.MapKey
	value bpf.MapValue
}

type mapSnapshot = []mapKeyValue

// mapSnapshots holds in-memory snapshots of all LB maps for use in tests.
type mapSnapshots struct {
	mu lock.Mutex

	services mapSnapshot
	backends mapSnapshot
	revNat   mapSnapshot
	affinity mapSnapshot
	srcRange mapSnapshot
}

func (s *mapSnapshots) snapshot(lbmaps LBMaps) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	svcCB := func(svcKey ServiceKey, svcValue ServiceValue) {
		s.services = append(s.services, mapKeyValue{svcKey, svcValue})
	}
	if err := lbmaps.DumpService(svcCB); err != nil {
		return fmt.Errorf("DumpService: %w", err)
	}

	beCB := func(beKey BackendKey, beValue BackendValue) {
		s.backends = append(s.backends, mapKeyValue{beKey, beValue})
	}
	if err := lbmaps.DumpBackend(beCB); err != nil {
		return fmt.Errorf("DumpBackend: %w", err)
	}

	revCB := func(revKey RevNatKey, revValue RevNatValue) {
		s.revNat = append(s.revNat, mapKeyValue{revKey, revValue})
	}
	if err := lbmaps.DumpRevNat(revCB); err != nil {
		return fmt.Errorf("DumpRevNat: %w", err)
	}

	affCB := func(affKey *AffinityMatchKey, affValue *AffinityMatchValue) {
		s.affinity = append(s.revNat, mapKeyValue{affKey, affValue})
	}
	if err := lbmaps.DumpAffinityMatch(affCB); err != nil {
		return fmt.Errorf("DumpAffinityMatch: %w", err)
	}

	srcRangeCB := func(key SourceRangeKey, value *SourceRangeValue) {
		s.srcRange = append(s.srcRange, mapKeyValue{key, value})
	}
	if err := lbmaps.DumpSourceRange(srcRangeCB); err != nil {
		return fmt.Errorf("DumpSourceRange: %w", err)
	}
	return nil
}

// restore the snapshot. If [anyProto] is true the protocol for services and backends is
// ignored and 'ANY' is used instead. This is for testing migration from Cilium version
// that did not support protocol differentiation.
func (s *mapSnapshots) restore(lbmaps LBMaps, anyProto bool) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, kv := range s.services {
		key := kv.key.(ServiceKey)
		if anyProto {
			switch k := key.(type) {
			case *Service4Key:
				k.Proto = uint8(u8proto.ANY)
			case *Service6Key:
				k.Proto = uint8(u8proto.ANY)
			}
		}
		err = errors.Join(err, lbmaps.UpdateService(kv.key.(ServiceKey), kv.value.(ServiceValue)))
	}
	for _, kv := range s.backends {
		value := kv.value.(BackendValue)
		if anyProto {
			switch v := value.(type) {
			case *Backend4ValueV3:
				v.Proto = u8proto.ANY
			case *Backend6ValueV3:
				v.Proto = u8proto.ANY
			}
		}
		err = errors.Join(err, lbmaps.UpdateBackend(kv.key.(BackendKey), value))
	}
	for _, kv := range s.revNat {
		err = errors.Join(err, lbmaps.UpdateRevNat(kv.key.(RevNatKey), kv.value.(RevNatValue)))
	}
	for _, kv := range s.affinity {
		err = errors.Join(err, lbmaps.UpdateAffinityMatch(kv.key.(*AffinityMatchKey), kv.value.(*AffinityMatchValue)))
	}
	for _, kv := range s.srcRange {
		err = errors.Join(err, lbmaps.UpdateSourceRange(kv.key.(SourceRangeKey), kv.value.(*SourceRangeValue)))
	}
	return
}

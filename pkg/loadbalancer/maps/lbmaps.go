// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"reflect"
	"unsafe"

	"github.com/cilium/ebpf"
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

type kvpair struct {
	a, b any
}
type fakeBPFMap struct {
	lock.Map[string, kvpair]
}

func (fm *fakeBPFMap) delete(key bpf.MapKey) error {
	fm.Map.Delete(bpfKey(key))
	return nil
}

func (fm *fakeBPFMap) update(key bpf.MapKey, value any) error {
	fm.Map.Store(bpfKey(key), kvpair{key, value})
	return nil
}

func (fm *fakeBPFMap) exists(key bpf.MapKey) bool {
	_, exists := fm.Map.Load(bpfKey(key))
	return exists
}

func (fm *fakeBPFMap) lookup(key bpf.MapKey) (any, error) {
	v, exists := fm.Map.Load(bpfKey(key))
	if !exists {
		return nil, ebpf.ErrKeyNotExist
	}
	return v.b, nil
}

func (fm *fakeBPFMap) IsEmpty() bool {
	return fm.Map.IsEmpty()
}

func bpfKey(key any) string {
	v := reflect.ValueOf(key)
	size := int(v.Type().Elem().Size())
	keyBytes := unsafe.Slice((*byte)(v.UnsafePointer()), size)
	return string(keyBytes)
}

func dumpFakeBPFMap[K any, V any](m *fakeBPFMap, cb func(K, V)) {
	m.Range(func(_ string, pair kvpair) bool {
		cb(pair.a.(K), pair.b.(V))
		return true
	})
}

type FakeLBMaps struct {
	aff        fakeBPFMap
	be         fakeBPFMap
	svc        fakeBPFMap
	revNat     fakeBPFMap
	sockRevNat fakeBPFMap
	srcRange   fakeBPFMap
	mglv4      fakeBPFMap
	mglv6      fakeBPFMap
	inners     lock.Map[uint32, *fakeBPFMap]
	nextID     uint32
}

func NewFakeLBMaps() LBMaps {
	return &FakeLBMaps{}
}

// DeleteAffinityMatch implements lbmaps.
func (f *FakeLBMaps) DeleteAffinityMatch(key *AffinityMatchKey) error {
	return f.aff.delete(key)
}

// DeleteBackend implements lbmaps.
func (f *FakeLBMaps) DeleteBackend(key BackendKey) error {
	return f.be.delete(key)
}

// DeleteRevNat implements lbmaps.
func (f *FakeLBMaps) DeleteRevNat(key RevNatKey) error {
	return f.revNat.delete(key)
}

// DeleteService implements lbmaps.
func (f *FakeLBMaps) DeleteService(key ServiceKey) error {
	return f.svc.delete(key)
}

// DeleteSourceRange implements lbmaps.
func (f *FakeLBMaps) DeleteSourceRange(key SourceRangeKey) error {
	return f.srcRange.delete(key)
}

// DumpAffinityMatch implements lbmaps.
func (f *FakeLBMaps) DumpAffinityMatch(cb func(*AffinityMatchKey, *AffinityMatchValue)) error {
	dumpFakeBPFMap(&f.aff, cb)
	return nil
}

// DumpBackend implements lbmaps.
func (f *FakeLBMaps) DumpBackend(cb func(BackendKey, BackendValue)) error {
	dumpFakeBPFMap(&f.be, cb)
	return nil
}

// DumpRevNat implements lbmaps.
func (f *FakeLBMaps) DumpRevNat(cb func(RevNatKey, RevNatValue)) error {
	dumpFakeBPFMap(&f.revNat, cb)
	return nil
}

// DumpService implements lbmaps.
func (f *FakeLBMaps) DumpService(cb func(ServiceKey, ServiceValue)) error {
	dumpFakeBPFMap(&f.svc, cb)
	return nil
}

// DumpSourceRange implements lbmaps.
func (f *FakeLBMaps) DumpSourceRange(cb func(SourceRangeKey, *SourceRangeValue)) error {
	dumpFakeBPFMap(&f.srcRange, cb)
	return nil
}

// UpdateAffinityMatch implements lbmaps.
func (f *FakeLBMaps) UpdateAffinityMatch(key *AffinityMatchKey, value *AffinityMatchValue) error {
	return f.aff.update(key, value)
}

// UpdateBackend implements lbmaps.
func (f *FakeLBMaps) UpdateBackend(key BackendKey, value BackendValue) error {
	return f.be.update(key, value)
}

// UpdateRevNat implements lbmaps.
func (f *FakeLBMaps) UpdateRevNat(key RevNatKey, value RevNatValue) error {
	return f.revNat.update(key, value)
}

// UpdateService implements lbmaps.
func (f *FakeLBMaps) UpdateService(key ServiceKey, value ServiceValue) error {
	return f.svc.update(key, value)
}

// UpdateSourceRange implements lbmaps.
func (f *FakeLBMaps) UpdateSourceRange(key SourceRangeKey, value *SourceRangeValue) error {
	return f.srcRange.update(key, value)
}

// UpdateMaglev implements lbmaps.
func (f *FakeLBMaps) UpdateMaglev(key MaglevOuterKey, backendIDs []loadbalancer.BackendID, ipv6 bool) error {
	var outer *fakeBPFMap
	if ipv6 {
		outer = &f.mglv6
	} else {
		outer = &f.mglv4
	}
	var singletonKey MaglevInnerKey
	inner := &fakeBPFMap{}
	currentID := f.nextID
	f.nextID++
	f.inners.Store(currentID, inner)
	value := MaglevOuterVal{
		FD: currentID,
	}
	if err := inner.update(&singletonKey, backendIDs); err != nil {
		return err
	}
	if err := outer.update(&key, value); err != nil {
		return err
	}
	return nil
}

// DeleteMaglev implements lbmaps.
func (f *FakeLBMaps) DeleteMaglev(key MaglevOuterKey, ipv6 bool) error {
	if ipv6 {
		return f.mglv6.delete(&key)
	} else {
		return f.mglv4.delete(&key)
	}
}

func (f *FakeLBMaps) DumpMaglev(cb func(MaglevOuterKey, MaglevOuterVal, MaglevInnerKey, *MaglevInnerVal, bool)) error {
	var err error
	cbWrap := func(key MaglevOuterKey, value MaglevOuterVal, ipv6 bool) bool {
		singletonKey := MaglevInnerKey{}
		innerMap, ok := f.inners.Load(value.FD)
		if !ok {
			err = fmt.Errorf("inner map %d not found", value.FD)
			return false
		}
		innerValue, ok := innerMap.Map.Load(bpfKey(&singletonKey))
		if !ok {
			err = fmt.Errorf("failed to fetch the value from the inner map for RevNatID=%d and FD=%d", key.RevNatID, value.FD)
			return false
		}
		cb(key, value, *innerValue.a.(*MaglevInnerKey), &MaglevInnerVal{BackendIDs: innerValue.b.([]loadbalancer.BackendID)}, ipv6)
		return true
	}
	f.mglv4.Range(func(_ string, pair kvpair) bool {
		return cbWrap(*pair.a.(*MaglevOuterKey), pair.b.(MaglevOuterVal), false)
	})
	f.mglv6.Range(func(_ string, pair kvpair) bool {
		return cbWrap(*pair.a.(*MaglevOuterKey), pair.b.(MaglevOuterVal), true)
	})
	return err
}

// DeleteSockRevNat implements LBMaps.
func (f *FakeLBMaps) DeleteSockRevNat(cookie uint64, addr net.IP, port uint16) error {
	var key bpf.MapKey
	if addr.To4() != nil {
		key4 := NewSockRevNat4Key(cookie, addr, port)
		key = key4
	} else {
		key6 := NewSockRevNat6Key(cookie, addr, port)
		key = key6
	}
	return f.sockRevNat.delete(key)
}

// UpdateSockRevNat implements LBMaps.
func (f *FakeLBMaps) UpdateSockRevNat(cookie uint64, addr net.IP, port uint16, revNatIndex uint16) error {
	var key bpf.MapKey
	var value bpf.MapValue
	if addr.To4() != nil {
		key4 := NewSockRevNat4Key(cookie, addr, port)
		key = key4
		value = &SockRevNat4Value{
			Address:     key4.Address,
			Port:        key4.Port,
			RevNatIndex: revNatIndex,
		}
	} else {
		key6 := NewSockRevNat6Key(cookie, addr, port)
		key = key6
		value = &SockRevNat6Value{
			Address:     key6.Address,
			Port:        key6.Port,
			RevNatIndex: revNatIndex,
		}
	}
	f.sockRevNat.update(key, value)
	return nil
}

func (f *FakeLBMaps) ExistsSockRevNat(cookie uint64, addr net.IP, port uint16) bool {
	var key bpf.MapKey
	if addr.To4() != nil {
		key4 := NewSockRevNat4Key(cookie, addr, port)
		key = key4
	} else {
		key6 := NewSockRevNat6Key(cookie, addr, port)
		key = key6
	}
	return f.sockRevNat.exists(key)
}

func (f *FakeLBMaps) SockRevNat() (*bpf.Map, *bpf.Map) {
	return nil, nil
}

// LookupBackend implements LBMaps.
func (f *FakeLBMaps) LookupBackend(key BackendKey) (BackendValue, error) {
	v, err := f.be.lookup(key)
	if err != nil {
		return nil, err
	}
	return v.(BackendValue), nil
}

// IsEmpty implements lbmaps.
func (f *FakeLBMaps) IsEmpty() bool {
	return f.aff.IsEmpty() &&
		f.be.IsEmpty() &&
		f.svc.IsEmpty() &&
		f.revNat.IsEmpty() &&
		f.srcRange.IsEmpty()
}

var _ LBMaps = &FakeLBMaps{}

type mapKeyValue struct {
	key   bpf.MapKey
	value bpf.MapValue
}
type mapSnapshot = []mapKeyValue

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

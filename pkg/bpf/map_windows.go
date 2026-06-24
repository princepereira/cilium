// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"context"
	"fmt"
	"iter"
	"log/slog"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// MapKey is the interface all BPF map keys must implement.
type MapKey interface {
	fmt.Stringer
	New() MapKey
}

// MapValue is the interface all BPF map values must implement.
type MapValue interface {
	fmt.Stringer
	New() MapValue
}

// MapPerCPUValue is the same as MapValue, but for per-CPU maps.
type MapPerCPUValue interface {
	MapValue
	NewSlice() any
}

type cacheEntry struct {
	Key   MapKey
	Value MapValue

	DesiredAction DesiredAction
	LastError     error
}

// DumpCallback is the callback type for map dump operations.
type DumpCallback func(key MapKey, value MapValue)

// DumpPerCPUCallback is the callback type for per-CPU map dump operations.
type DumpPerCPUCallback func(key MapKey, values any)

// Map represents a BPF map. On Windows this is a stub; actual map operations
// are delegated to cncshim via platform-specific map implementations.
type Map struct {
	Logger *slog.Logger
	m      *ebpf.Map
	spec   *ebpf.MapSpec

	key   MapKey
	value MapValue

	name string
	path string
	lock lock.RWMutex

	cachedCommonName string
	enableSync       bool
	withValueCache   bool
	cache            map[string]*cacheEntry

	errorResolverLastScheduled time.Time
	outstandingErrors          bool
	pressureGauge              *metrics.GaugeWithThreshold
	eventsBufferEnabled        bool
	events                     *eventsBuffer
	group                      string
}

func (m *Map) Type() ebpf.MapType {
	if m.spec != nil {
		return m.spec.Type
	}
	return ebpf.UnspecifiedMap
}

func (m *Map) KeySize() uint32 {
	if m.spec != nil {
		return m.spec.KeySize
	}
	return 0
}

func (m *Map) ValueSize() uint32 {
	if m.spec != nil {
		return m.spec.ValueSize
	}
	return 0
}

func (m *Map) MaxEntries() uint32 {
	if m.spec != nil {
		return m.spec.MaxEntries
	}
	return 0
}

func (m *Map) Flags() uint32 {
	if m.spec != nil {
		return m.spec.Flags
	}
	return 0
}

func (m *Map) NonPrefixedName() string {
	return extractCommonName(m.name)
}

func (m *Map) WithCache() *Map {
	m.withValueCache = true
	m.cache = make(map[string]*cacheEntry)
	return m
}

func (m *Map) WithEvents(c option.BPFEventBufferConfig) *Map {
	if c.Enabled {
		m.eventsBufferEnabled = true
	}
	return m
}

func (m *Map) WithGroupName(group string) *Map {
	m.group = group
	return m
}

func (m *Map) WithPressureMetricThreshold(registry *metrics.Registry, threshold float64) *Map {
	return m
}

func (m *Map) WithPressureMetric(registry *metrics.Registry) *Map {
	return m
}

func (m *Map) UpdatePressureMetricWithSize(size int32) {}

func (m *Map) FD() int { return -1 }

func (m *Map) Name() string { return m.name }

func (m *Map) Path() (string, error) { return m.path, nil }

func (m *Map) Unpin() error { return nil }

func (m *Map) UnpinIfExists() error { return nil }

func (m *Map) Recreate() error { return nil }

func (m *Map) IsOpen() bool { return false }

func (m *Map) OpenOrCreate() error { return nil }

func (m *Map) CreateUnpinned() error { return nil }

func (m *Map) Create() error { return nil }

func (m *Map) Open() error { return nil }

func (m *Map) Close() error { return nil }

func (m *Map) NextKey(key, nextKeyOut any) error {
	return fmt.Errorf("not supported on Windows")
}

func (m *Map) DumpWithCallback(cb DumpCallback) error { return nil }

func (m *Map) DumpPerCPUWithCallback(cb DumpPerCPUCallback) error { return nil }

func (m *Map) DumpWithCallbackIfExists(cb DumpCallback) error { return nil }

func (m *Map) DumpReliablyWithCallback(cb DumpCallback, stats *DumpStats) error { return nil }

func (m *Map) Dump(hash map[string][]string) error { return nil }

func (m *Map) BatchLookup(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error) {
	return 0, fmt.Errorf("not supported on Windows")
}

func (m *Map) DumpIfExists(hash map[string][]string) error { return nil }

func (m *Map) Lookup(key MapKey) (MapValue, error) {
	return nil, fmt.Errorf("not supported on Windows")
}

func (m *Map) Update(key MapKey, value MapValue) error { return nil }

func (m *Map) SilentDelete(key MapKey) (deleted bool, err error) { return false, nil }

func (m *Map) Delete(key MapKey) error { return nil }

func (m *Map) DeleteLocked(key MapKey) error { return nil }

func (m *Map) DeleteAll() error { return nil }

func (m *Map) ClearAll() error { return nil }

func (m *Map) GetModel() *models.BPFMap { return &models.BPFMap{Path: m.path} }

func (m *Map) BatchCount() (int, error) { return 0, nil }

// NewMap creates a new Map instance. On Windows, this creates a stub map.
func NewMap(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue,
	maxEntries int, flags uint32) *Map {
	return &Map{
		name:  name,
		key:   mapKey,
		value: mapValue,
		spec: &ebpf.MapSpec{
			Name:       name,
			Type:       mapType,
			MaxEntries: uint32(maxEntries),
			Flags:      flags,
		},
	}
}

// NewMapWithInnerSpec creates a new Map with an inner map spec. Stub on Windows.
func NewMapWithInnerSpec(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue,
	maxEntries int, flags uint32, innerSpec *ebpf.MapSpec) *Map {
	return NewMap(name, mapType, mapKey, mapValue, maxEntries, flags)
}

// OpenMap opens an existing BPF map. Stub on Windows.
func OpenMap(pinPath string, key MapKey, value MapValue) (*Map, error) {
	return nil, fmt.Errorf("not supported on Windows")
}

// BatchIterator types for Windows (stubs)
type KeyPointer[KT any] interface {
	*KT
}

type ValuePointer[VT any] interface {
	*VT
}

type BatchIterator[KT any, VT any, KP KeyPointer[KT], VP ValuePointer[VT]] struct{}

type BatchIteratorOpt[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]] func(*BatchIterator[KT, VT, KP, VP])

func NewBatchIterator[KT any, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](m *Map) *BatchIterator[KT, VT, KP, VP] {
	return &BatchIterator[KT, VT, KP, VP]{}
}

func WithEBPFBatchOpts[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](opts *ebpf.BatchOptions) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(b *BatchIterator[KT, VT, KP, VP]) {}
}

func WithMaxRetries[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](retries uint32) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(b *BatchIterator[KT, VT, KP, VP]) {}
}

func WithStartingChunkSize[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](size int) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(b *BatchIterator[KT, VT, KP, VP]) {}
}

func CountAll[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](ctx context.Context, it *BatchIterator[KT, VT, KP, VP]) (int, error) {
	return 0, nil
}

// IterateAll returns an empty iterator on Windows.
func (bi *BatchIterator[KT, VT, KP, VP]) IterateAll(ctx context.Context, opts ...BatchIteratorOpt[KT, VT, KP, VP]) iter.Seq2[KP, VP] {
	return func(yield func(KP, VP) bool) {}
}

// Err returns the last error encountered during iteration (always nil on Windows).
func (bi *BatchIterator[KT, VT, KP, VP]) Err() error {
	return nil
}

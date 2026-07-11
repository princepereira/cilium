// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bpf

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// ErrMaxLookup is returned when the maximum number of map element lookups has
	// been reached.
	ErrMaxLookup = errors.New("maximum number of lookups reached")

	// ErrMapNotOpened is returned when the MapOps is used with a BPF map that is not open yet.
	ErrMapNotOpened = errors.New("BPF map has not been opened")

	errNotSupported = errors.New("not supported on this platform")
)

const (
	// PinReplace matches CILIUM_PIN_REPLACE.
	PinReplace = ebpf.PinType(1 << 4)
)

type MapKey interface {
	fmt.Stringer

	// New must return a pointer to a new MapKey.
	New() MapKey
}

type MapValue interface {
	fmt.Stringer

	// New must return a pointer to a new MapValue.
	New() MapValue
}

// MapPerCPUValue is the same as MapValue, but for per-CPU maps. Implement to be
// able to fetch map values from all CPUs.
type MapPerCPUValue interface {
	MapValue

	// NewSlice must return a pointer to a slice of structs that implement MapValue.
	NewSlice() any
}

type cacheEntry struct {
	Key   MapKey
	Value MapValue

	DesiredAction DesiredAction
	LastError     error
}

type Map struct {
	Logger *slog.Logger

	spec  *ebpf.MapSpec
	key   MapKey
	value MapValue

	name string
	path string

	group string
}

func NewMap(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue, maxEntries int, flags uint32) *Map {
	return &Map{
		Logger: logging.DefaultSlogLogger,
		spec: &ebpf.MapSpec{
			Type:       mapType,
			Name:       filepath.Base(name),
			MaxEntries: uint32(maxEntries),
			Flags:      flags,
		},
		name:  filepath.Base(name),
		key:   mapKey,
		value: mapValue,
		group: name,
	}
}

func NewMapFromRegistry(reg *registry.MapRegistry, name string, mapKey MapKey, mapValue MapValue) (*Map, error) {
	spec, err := reg.Get(name)
	if err != nil {
		return nil, fmt.Errorf("get map from registry: %w", err)
	}

	return &Map{
		Logger: logging.DefaultSlogLogger,
		spec:   spec,
		name:   spec.Name,
		key:    mapKey,
		value:  mapValue,
		group:  spec.Name,
	}, nil
}

func NewMapWithInnerSpec(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue, maxEntries int, flags uint32, innerSpec *ebpf.MapSpec) *Map {
	m := NewMap(name, mapType, mapKey, mapValue, maxEntries, flags)
	m.spec.InnerMap = innerSpec
	return m
}

func OpenMap(pinPath string, key MapKey, value MapValue) (*Map, error) {
	return nil, errNotSupported
}

func (m *Map) Type() ebpf.MapType {
	if m != nil && m.spec != nil {
		return m.spec.Type
	}
	return ebpf.UnspecifiedMap
}

func (m *Map) BatchCount() (count int, err error) { return 0, errNotSupported }
func (m *Map) KeySize() uint32 {
	if m != nil && m.spec != nil {
		return m.spec.KeySize
	}
	return 0
}
func (m *Map) ValueSize() uint32 {
	if m != nil && m.spec != nil {
		return m.spec.ValueSize
	}
	return 0
}
func (m *Map) MaxEntries() uint32 {
	if m != nil && m.spec != nil {
		return m.spec.MaxEntries
	}
	return 0
}
func (m *Map) Flags() uint32 {
	if m != nil && m.spec != nil {
		return m.spec.Flags
	}
	return 0
}
func (m *Map) NonPrefixedName() string {
	return strings.TrimPrefix(m.name, metrics.Namespace+"_")
}
func (m *Map) WithCache() *Map                               { return m }
func (m *Map) WithEvents(c option.BPFEventBufferConfig) *Map { return m }
func (m *Map) WithGroupName(group string) *Map               { m.group = group; return m }
func (m *Map) WithPressureMetricThreshold(registry *metrics.Registry, threshold float64) *Map {
	return m
}
func (m *Map) WithPressureMetric(registry *metrics.Registry) *Map { return m }
func (m *Map) UpdatePressureMetricWithSize(size int32)            {}
func (m *Map) FD() int                                            { return -1 }
func (m *Map) Name() string                                       { return m.name }
func (m *Map) Path() (string, error) {
	if m.path != "" {
		return m.path, nil
	}
	if m.name == "" {
		return "", errors.New("either path or name must be set")
	}
	return MapPath(m.Logger, m.name), nil
}
func (m *Map) Unpin() error                           { return errNotSupported }
func (m *Map) UnpinIfExists() error                   { return nil }
func (m *Map) Recreate() error                        { return errNotSupported }
func (m *Map) IsOpen() bool                           { return false }
func (m *Map) OpenOrCreate() error                    { return errNotSupported }
func (m *Map) CreateUnpinned() error                  { return errNotSupported }
func (m *Map) Create() error                          { return errNotSupported }
func (m *Map) Open() error                            { return errNotSupported }
func (m *Map) Close() error                           { return nil }
func (m *Map) NextKey(key, nextKeyOut any) error      { return errNotSupported }
func (m *Map) DumpWithCallback(cb DumpCallback) error { return errNotSupported }
func (m *Map) DumpPerCPUWithCallback(cb DumpPerCPUCallback) error {
	return errNotSupported
}
func (m *Map) DumpWithCallbackIfExists(cb DumpCallback) error { return nil }
func (m *Map) DumpReliablyWithCallback(cb DumpCallback, stats *DumpStats) error {
	return errNotSupported
}
func (m *Map) Dump(hash map[string][]string) error { return errNotSupported }
func (m *Map) BatchLookup(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error) {
	return 0, errNotSupported
}
func (m *Map) DumpIfExists(hash map[string][]string) error { return nil }
func (m *Map) Lookup(key MapKey) (MapValue, error)         { return nil, errNotSupported }
func (m *Map) Update(key MapKey, value MapValue) error     { return errNotSupported }
func (m *Map) SilentDelete(key MapKey) (deleted bool, err error) {
	return false, errNotSupported
}
func (m *Map) Delete(key MapKey) error       { return errNotSupported }
func (m *Map) DeleteLocked(key MapKey) error { return errNotSupported }
func (m *Map) DeleteAll() error              { return errNotSupported }
func (m *Map) ClearAll() error               { return errNotSupported }
func (m *Map) GetModel() *models.BPFMap {
	path, _ := m.Path()
	return &models.BPFMap{Path: path}
}
func (m *Map) DumpAndSubscribe(ctx context.Context, callback EventCallbackFunc, follow bool) {}
func (m *Map) IsEventsEnabled() bool                                                         { return false }

type DumpCallback func(key MapKey, value MapValue)
type DumpPerCPUCallback func(key MapKey, values any)

// BatchIterator provides a typed wrapper *Map that allows for batched iteration
// of bpf maps.
type BatchIterator[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]] struct {
	err error
}

func NewBatchIterator[KT any, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](m *Map) *BatchIterator[KT, VT, KP, VP] {
	return &BatchIterator[KT, VT, KP, VP]{}
}

type KeyPointer[T any] interface {
	MapKey
	*T
}

type ValuePointer[T any] interface {
	MapValue
	*T
}

func (bi BatchIterator[KT, VT, KP, VP]) Err() error { return bi.err }

type BatchIteratorOpt[KT any, VT any, KP KeyPointer[KT], VP ValuePointer[VT]] func(*BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP]

func WithEBPFBatchOpts[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](opts *ebpf.BatchOptions) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(in *BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP] { return in }
}

func WithMaxRetries[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](retries uint32) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(in *BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP] { return in }
}

func WithStartingChunkSize[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](size int) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(in *BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP] { return in }
}

func CountAll[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](ctx context.Context, iter *BatchIterator[KT, VT, KP, VP]) (int, error) {
	return 0, iter.Err()
}

func (bi *BatchIterator[KT, VT, KP, VP]) IterateAll(ctx context.Context, opts ...BatchIteratorOpt[KT, VT, KP, VP]) iter.Seq2[KP, VP] {
	bi.err = errNotSupported
	return func(yield func(KP, VP) bool) {}
}

// DumpStats tracks statistics over the dump of a map.
type DumpStats struct {
	Started            time.Time
	Finished           time.Time
	Lookup             uint32
	LookupFailed       uint32
	PrevKeyUnavailable uint32
	KeyFallback        uint32
	MaxEntries         uint32
	Interrupted        uint32
	Completed          bool
}

func NewDumpStats(m *Map) *DumpStats {
	return &DumpStats{MaxEntries: m.MaxEntries()}
}
func (d *DumpStats) Start()                  { d.Started = time.Now() }
func (d *DumpStats) Finish()                 { d.Finished = time.Now() }
func (d *DumpStats) Duration() time.Duration { return d.Finished.Sub(d.Started) }

func BPFFSRoot() string { return defaults.BPFFSRoot }
func TCGlobalsPath() string {
	return filepath.Join(defaults.BPFFSRoot, defaults.TCGlobalsPath)
}
func CiliumPath() string         { return filepath.Join(defaults.BPFFSRoot, "cilium") }
func MkdirBPF(path string) error { return errNotSupported }
func Remove(path string) error   { return errNotSupported }
func MapPath(logger *slog.Logger, name string) string {
	return filepath.Join(TCGlobalsPath(), name)
}
func LocalMapName(name string, id uint16) string {
	return fmt.Sprintf("%s%05d", name, id)
}
func LocalMapPath(logger *slog.Logger, name string, id uint16) string {
	return MapPath(logger, LocalMapName(name, id))
}
func CheckOrMountFS(logger *slog.Logger, bpfRoot string) {}

func OpenOrCreateMap(logger *slog.Logger, spec *ebpf.MapSpec, pinDir string) (*ebpf.Map, error) {
	return nil, errNotSupported
}
func GetMtime() (uint64, error) { return 0, errNotSupported }

func GetMap(logger *slog.Logger, name string) *Map { return nil }
func GetOpenMaps() []*models.BPFMap                { return nil }

func EnableMapPreAllocation()                 {}
func DisableMapPreAllocation()                {}
func EnableMapDistributedLRU()                {}
func DisableMapDistributedLRU()               {}
func GetMapMemoryFlags(t ebpf.MapType) uint32 { return 0 }

// Action describes an action for map buffer events.
type Action uint8

const (
	MapUpdate Action = iota
	MapDelete
	MapDeleteAll
)

func (e Action) String() string {
	switch e {
	case MapUpdate:
		return "update"
	case MapDelete:
		return "delete"
	case MapDeleteAll:
		return "delete-all"
	default:
		return "unknown"
	}
}

// Event contains data about a bpf operation event.
type Event struct {
	Timestamp time.Time
	action    Action
	cacheEntry
}

func (e *Event) GetAction() string { return e.action.String() }
func (e Event) GetKey() string {
	if e.cacheEntry.Key == nil {
		return "<nil>"
	}
	return e.cacheEntry.Key.String()
}
func (e Event) GetValue() string {
	if e.cacheEntry.Value == nil {
		return "<nil>"
	}
	return e.cacheEntry.Value.String()
}
func (e Event) GetLastError() error             { return e.cacheEntry.LastError }
func (e Event) GetDesiredAction() DesiredAction { return e.cacheEntry.DesiredAction }

type EventCallbackFunc func(Event)

func IsTailCall(prog *ebpf.ProgramSpec) bool { return false }

func LoadAndAssign(logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *CollectionOptions) (func() error, error) {
	return nil, errNotSupported
}

type CollectionOptions struct {
	ebpf.CollectionOptions

	Constants       any
	MapRenames      []map[string]string
	MapReplacements map[string]*Map
	Keep            *set.Set[string]
	ConfigDumpPath  string
	MapRegistry     *registry.MapRegistry
	ProgramPatches  map[string]func(asm.Instructions) (asm.Instructions, error)
}

func LoadCollection(logger *slog.Logger, spec *ebpf.CollectionSpec, opts *CollectionOptions) (*ebpf.Collection, func() error, error) {
	return nil, nil, errNotSupported
}

// KeyValue is the interface that an BPF map value object must implement.
type KeyValue interface {
	BinaryKey() encoding.BinaryMarshaler
	BinaryValue() encoding.BinaryMarshaler
}

// StructBinaryMarshaler implements a BinaryMarshaler for a struct of primitive fields.
type StructBinaryMarshaler struct {
	Target any
}

func (m StructBinaryMarshaler) MarshalBinary() ([]byte, error) {
	v := reflect.ValueOf(m.Target)
	size := int(v.Type().Elem().Size())
	return unsafe.Slice((*byte)(v.UnsafePointer()), size), nil
}

type mapOps[KV KeyValue] struct{}

func NewMapOps[KV KeyValue](m *Map) reconciler.Operations[KV] {
	return &mapOps[KV]{}
}

func (ops *mapOps[KV]) Delete(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, entry KV) error {
	return errNotSupported
}
func (ops *mapOps[KV]) Prune(ctx context.Context, txn statedb.ReadTxn, objs iter.Seq2[KV, statedb.Revision]) error {
	return errNotSupported
}
func (ops *mapOps[KV]) Update(ctx context.Context, txn statedb.ReadTxn, _ statedb.Revision, entry KV) error {
	return errNotSupported
}

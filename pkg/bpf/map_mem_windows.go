// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bpf

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/lock"
)

// The eBPF datapath is not available on non-Linux platforms: the cilium/ebpf
// library relies on the eBPF-for-Windows runtime (ebpfapi.dll), which is not a
// hard requirement for running the agent's control plane. To keep the agent
// runnable, BPF maps are backed by a process-local, in-memory key/value store
// that mirrors the small subset of the *ebpf.Map API consumed by pkg/bpf.
//
// This is a best-effort dummy datapath: writes are retained in memory and can
// be read back and iterated, but no kernel/datapath program ever consumes them.
// Real datapath programming on Windows is expected to flow through dedicated
// components (e.g. cncshim/hnslib) at a higher, semantic layer.

// memEntry is a single serialized key/value pair.
type memEntry struct {
	key   []byte
	value []byte
}

// memMap is an in-memory stand-in for *ebpf.Map. Its exported method set
// mirrors the subset of *ebpf.Map used by the Map wrapper in map_windows.go so
// that the higher-level logic can remain unchanged.
type memMap struct {
	mu    lock.RWMutex
	order []string // marshaled-key strings, in insertion order
	store map[string]memEntry

	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapType    ebpf.MapType
	flags      uint32
}

func newMemMap(spec *ebpf.MapSpec) *memMap {
	mm := &memMap{store: make(map[string]memEntry)}
	if spec != nil {
		mm.keySize = spec.KeySize
		mm.valueSize = spec.ValueSize
		mm.maxEntries = spec.MaxEntries
		mm.mapType = spec.Type
		mm.flags = spec.Flags
	}
	return mm
}

func (mm *memMap) Type() ebpf.MapType { return mm.mapType }
func (mm *memMap) KeySize() uint32    { return mm.keySize }
func (mm *memMap) ValueSize() uint32  { return mm.valueSize }
func (mm *memMap) MaxEntries() uint32 { return mm.maxEntries }
func (mm *memMap) Flags() uint32      { return mm.flags }

// FD returns an invalid file descriptor: there is no kernel object backing the
// in-memory map.
func (mm *memMap) FD() int { return -1 }

func (mm *memMap) Close() error { return nil }

// Unpin is a no-op: there is no BPF filesystem pin backing an in-memory map.
func (mm *memMap) Unpin() error { return nil }

// IsPinned always reports false for the in-memory backend.
func (mm *memMap) IsPinned() bool { return false }

func (mm *memMap) Lookup(key, valueOut any) error {
	kb, err := memMarshal(key)
	if err != nil {
		return err
	}

	mm.mu.RLock()
	defer mm.mu.RUnlock()

	e, ok := mm.store[string(kb)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	return memUnmarshal(e.value, valueOut)
}

func (mm *memMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	kb, err := memMarshal(key)
	if err != nil {
		return err
	}
	vb, err := memMarshal(value)
	if err != nil {
		return err
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	ks := string(kb)
	if _, ok := mm.store[ks]; !ok {
		mm.order = append(mm.order, ks)
	}
	// Copy to avoid aliasing caller-owned buffers.
	mm.store[ks] = memEntry{key: append([]byte(nil), kb...), value: append([]byte(nil), vb...)}
	return nil
}

func (mm *memMap) Delete(key any) error {
	kb, err := memMarshal(key)
	if err != nil {
		return err
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	ks := string(kb)
	if _, ok := mm.store[ks]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(mm.store, ks)
	for i, k := range mm.order {
		if k == ks {
			mm.order = append(mm.order[:i], mm.order[i+1:]...)
			break
		}
	}
	return nil
}

// NextKey implements iteration akin to bpf_map_get_next_key: a nil key returns
// the first key, otherwise it returns the key following the given one.
func (mm *memMap) NextKey(key, nextKeyOut any) error {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if len(mm.order) == 0 {
		return ebpf.ErrKeyNotExist
	}

	if key == nil {
		return memUnmarshal(mm.store[mm.order[0]].key, nextKeyOut)
	}

	kb, err := memMarshal(key)
	if err != nil {
		return err
	}
	ks := string(kb)
	for i, k := range mm.order {
		if k == ks {
			if i+1 >= len(mm.order) {
				return ebpf.ErrKeyNotExist
			}
			return memUnmarshal(mm.store[mm.order[i+1]].key, nextKeyOut)
		}
	}
	// Key not found: restart iteration from the beginning, matching the kernel
	// behavior of returning the first key for a stale/removed cursor.
	return memUnmarshal(mm.store[mm.order[0]].key, nextKeyOut)
}

// Iterate returns a snapshot iterator over the map contents.
func (mm *memMap) Iterate() *memIterator {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	entries := make([]memEntry, 0, len(mm.order))
	for _, ks := range mm.order {
		entries = append(entries, mm.store[ks])
	}
	return &memIterator{entries: entries}
}

// BatchLookup is not implemented for the in-memory backend; iteration is done
// via Iterate/NextKey instead. Returning ErrKeyNotExist signals "no entries".
func (mm *memMap) BatchLookup(_ *ebpf.MapBatchCursor, _, _ any, _ *ebpf.BatchOptions) (int, error) {
	return 0, ebpf.ErrKeyNotExist
}

// Put mirrors ebpf.Map.Put: it inserts or overwrites the value for key.
func (mm *memMap) Put(key, value any) error {
	return mm.Update(key, value, ebpf.UpdateAny)
}

// NextKeyBytes mirrors ebpf.Map.NextKeyBytes, returning the raw bytes of the
// key following prev (or the first key when prev is nil). It returns (nil, nil)
// once iteration is exhausted.
func (mm *memMap) NextKeyBytes(prev []byte) ([]byte, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	if len(mm.order) == 0 {
		return nil, nil
	}
	if prev == nil {
		return []byte(mm.order[0]), nil
	}
	ps := string(prev)
	for i, k := range mm.order {
		if k == ps {
			if i+1 >= len(mm.order) {
				return nil, nil
			}
			return []byte(mm.order[i+1]), nil
		}
	}
	return []byte(mm.order[0]), nil
}

// memIterator mirrors the *ebpf.MapIterator surface used by the Map wrapper.
type memIterator struct {
	entries []memEntry
	pos     int
	err     error
}

func (it *memIterator) Next(keyOut, valueOut any) bool {
	if it.err != nil || it.pos >= len(it.entries) {
		return false
	}
	e := it.entries[it.pos]
	it.pos++
	if err := memUnmarshal(e.key, keyOut); err != nil {
		it.err = err
		return false
	}
	if err := memUnmarshal(e.value, valueOut); err != nil {
		it.err = err
		return false
	}
	return true
}

func (it *memIterator) Err() error { return it.err }

// memMarshal serializes a BPF map key or value into its byte representation,
// mirroring how cilium/ebpf marshals map keys/values.
func memMarshal(v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case []byte:
		return t, nil
	case encoding.BinaryMarshaler:
		return t.MarshalBinary()
	default:
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			return nil, fmt.Errorf("marshaling bpf map data of type %T: %w", v, err)
		}
		return buf.Bytes(), nil
	}
}

// memUnmarshal deserializes bytes into a BPF map key or value.
func memUnmarshal(data []byte, v any) error {
	switch t := v.(type) {
	case nil:
		return nil
	case *[]byte:
		*t = append((*t)[:0], data...)
		return nil
	case encoding.BinaryUnmarshaler:
		return t.UnmarshalBinary(data)
	default:
		return binary.Read(bytes.NewReader(data), binary.LittleEndian, v)
	}
}

// InMemoryMap is an exported handle to the in-memory BPF map backend so that
// other packages (e.g. pkg/ebpf) can reuse it on platforms without the eBPF
// runtime, instead of duplicating the marshalling and storage logic.
type InMemoryMap = memMap

// NewInMemoryMap creates a new, unpinned in-memory map from the given spec.
func NewInMemoryMap(spec *ebpf.MapSpec) *InMemoryMap { return newMemMap(spec) }

// OpenOrCreateInMemoryMap returns the pinned in-memory map for path, creating
// and registering it if it does not yet exist.
func OpenOrCreateInMemoryMap(path string, spec *ebpf.MapSpec) *InMemoryMap {
	return openOrCreateMemMap(path, spec, true)
}

// LoadInMemoryMap returns the pinned in-memory map for path, creating an empty
// one when none exists.
func LoadInMemoryMap(path string, spec *ebpf.MapSpec) *InMemoryMap {
	return loadMemMap(path, spec)
}

// pinnedMemMaps emulates BPF filesystem pinning: maps created with pinning are
// retained here by pin path so that re-opening (or a separate Map object for
// the same path) observes the same in-memory contents.
var (
	pinnedMemMapsMu lock.Mutex
	pinnedMemMaps   = make(map[string]*memMap)
)

func lookupPinnedMemMap(path string) (*memMap, bool) {
	pinnedMemMapsMu.Lock()
	defer pinnedMemMapsMu.Unlock()
	mm, ok := pinnedMemMaps[path]
	return mm, ok
}

func storePinnedMemMap(path string, mm *memMap) {
	pinnedMemMapsMu.Lock()
	defer pinnedMemMapsMu.Unlock()
	pinnedMemMaps[path] = mm
}

func removePinnedMemMap(path string) {
	pinnedMemMapsMu.Lock()
	defer pinnedMemMapsMu.Unlock()
	delete(pinnedMemMaps, path)
}

// openOrCreateMemMap returns the in-memory map for the given pin path, creating
// (and, when pin is set, registering) it if necessary.
func openOrCreateMemMap(path string, spec *ebpf.MapSpec, pin bool) *memMap {
	if pin {
		if mm, ok := lookupPinnedMemMap(path); ok {
			return mm
		}
	}
	mm := newMemMap(spec)
	if pin {
		storePinnedMemMap(path, mm)
	}
	return mm
}

// loadMemMap returns a previously pinned in-memory map for the given path, or a
// freshly created empty one when none exists.
func loadMemMap(path string, spec *ebpf.MapSpec) *memMap {
	if mm, ok := lookupPinnedMemMap(path); ok {
		return mm
	}
	mm := newMemMap(spec)
	storePinnedMemMap(path, mm)
	return mm
}

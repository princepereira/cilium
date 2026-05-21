// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// ErrMaxLookup is returned when the maximum number of map element lookups has
	// been reached.
	ErrMaxLookup = errors.New("maximum number of lookups reached")

	bpfMapSyncControllerGroup = controller.NewGroup("bpf-map-sync")
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

// MapPerCPUValue is the same as MapValue, but for per-CPU maps.
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

// Map represents a BPF map on Windows. It uses cilium/ebpf for eBPF for Windows
// map operations and can optionally be backed by cncshim for domain-specific
// operations at higher layers.
type Map struct {
	Logger *slog.Logger
	m      *ebpf.Map
	// spec will be nil after the map has been created
	spec *ebpf.MapSpec

	key   MapKey
	value MapValue

	name string
	path string
	lock lock.RWMutex

	// cachedCommonName is the common portion of the name excluding any
	// endpoint ID
	cachedCommonName string

	// enableSync is true when synchronization retries have been enabled.
	enableSync bool

	// withValueCache is true when map cache has been enabled
	withValueCache bool

	// cache as key/value entries when map cache is enabled or as key-only when
	// pressure metric is enabled
	cache map[string]*cacheEntry

	// errorResolverLastScheduled is the timestamp when the error resolver
	// was last scheduled
	errorResolverLastScheduled time.Time

	// outstandingErrors states whether there are outstanding errors
	outstandingErrors bool

	// pressureGauge is a metric that tracks the pressure on this map
	pressureGauge *metrics.GaugeWithThreshold

	// is true when events buffer is enabled.
	eventsBufferEnabled bool

	// contains optional event buffer which stores last n bpf map events.
	events *eventsBuffer

	// group is the metric group name for this map
	group string
}

func (m *Map) Type() ebpf.MapType {
	if m.m != nil {
		return m.m.Type()
	}
	if m.spec != nil {
		return m.spec.Type
	}
	return ebpf.UnspecifiedMap
}

func (m *Map) KeySize() uint32 {
	if m.m != nil {
		return m.m.KeySize()
	}
	if m.spec != nil {
		return m.spec.KeySize
	}
	return 0
}

func (m *Map) ValueSize() uint32 {
	if m.m != nil {
		return m.m.ValueSize()
	}
	if m.spec != nil {
		return m.spec.ValueSize
	}
	return 0
}

func (m *Map) MaxEntries() uint32 {
	if m.m != nil {
		return m.m.MaxEntries()
	}
	if m.spec != nil {
		return m.spec.MaxEntries
	}
	return 0
}

func (m *Map) Flags() uint32 {
	if m.m != nil {
		return m.m.Flags()
	}
	if m.spec != nil {
		return m.spec.Flags
	}
	return 0
}

func (m *Map) hasPerCPUValue() bool {
	mt := m.Type()
	return mt == ebpf.PerCPUHash || mt == ebpf.PerCPUArray || mt == ebpf.LRUCPUHash || mt == ebpf.PerCPUCGroupStorage
}

func (m *Map) updateMetrics() {
	if m.group == "" {
		return
	}
	metrics.UpdateMapCapacity(m.group, m.MaxEntries())
}

// NewMap creates a new Map instance - object representing a BPF map
func NewMap(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue,
	maxEntries int, flags uint32) *Map {

	defaultSlogLogger := logging.DefaultSlogLogger
	keySize := reflect.TypeOf(mapKey).Elem().Size()
	valueSize := reflect.TypeOf(mapValue).Elem().Size()

	return &Map{
		Logger: defaultSlogLogger.With(
			logfields.BPFMapPath, name,
			logfields.BPFMapName, name,
		),
		spec: &ebpf.MapSpec{
			Type:       mapType,
			Name:       path.Base(name),
			KeySize:    uint32(keySize),
			ValueSize:  uint32(valueSize),
			MaxEntries: uint32(maxEntries),
			Flags:      flags,
		},
		name:  path.Base(name),
		key:   mapKey,
		value: mapValue,
		group: name,
	}
}

// NewMapWithInnerSpec creates a new Map instance with an inner map specification
func NewMapWithInnerSpec(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue,
	maxEntries int, flags uint32, innerSpec *ebpf.MapSpec) *Map {

	defaultSlogLogger := logging.DefaultSlogLogger
	keySize := reflect.TypeOf(mapKey).Elem().Size()
	valueSize := reflect.TypeOf(mapValue).Elem().Size()

	return &Map{
		Logger: defaultSlogLogger.With(
			logfields.BPFMapPath, name,
			logfields.BPFMapName, name,
		),
		spec: &ebpf.MapSpec{
			Type:       mapType,
			Name:       path.Base(name),
			KeySize:    uint32(keySize),
			ValueSize:  uint32(valueSize),
			MaxEntries: uint32(maxEntries),
			Flags:      flags,
			InnerMap:   innerSpec,
		},
		name:  path.Base(name),
		key:   mapKey,
		value: mapValue,
	}
}

func (m *Map) commonName() string {
	if m.cachedCommonName != "" {
		return m.cachedCommonName
	}

	m.cachedCommonName = extractCommonName(m.name)
	return m.cachedCommonName
}

func (m *Map) NonPrefixedName() string {
	return strings.TrimPrefix(m.name, metrics.Namespace+"_")
}

// scheduleErrorResolver schedules a periodic resolver controller that scans
// all BPF map caches for unresolved errors and attempts to resolve them.
//
// m.lock must be held for writing
func (m *Map) scheduleErrorResolver() {
	m.outstandingErrors = true

	if time.Since(m.errorResolverLastScheduled) <= errorResolverSchedulerMinInterval {
		return
	}

	m.errorResolverLastScheduled = time.Now()

	go func() {
		time.Sleep(errorResolverSchedulerDelay)
		mapControllers.UpdateController(m.controllerName(),
			controller.ControllerParams{
				Group:       bpfMapSyncControllerGroup,
				DoFunc:      m.resolveErrors,
				RunInterval: errorResolverSchedulerMinInterval,
			},
		)
	}()
}

// WithCache enables use of a cache.
func (m *Map) WithCache() *Map {
	if m.cache == nil {
		m.cache = map[string]*cacheEntry{}
	}
	m.withValueCache = true
	m.enableSync = true
	return m
}

// WithEvents enables use of the event buffer.
func (m *Map) WithEvents(c option.BPFEventBufferConfig) *Map {
	if !c.Enabled {
		return m
	}
	m.Logger.Debug(
		"enabling events buffer",
		logfields.Size, c.MaxSize,
		logfields.TTL, c.TTL,
	)
	m.eventsBufferEnabled = true
	m.initEventsBuffer(c.MaxSize, c.TTL)
	return m
}

func (m *Map) WithGroupName(group string) *Map {
	m.group = group
	return m
}

// WithPressureMetricThreshold enables the tracking of a metric that measures
// the pressure of this map.
func (m *Map) WithPressureMetricThreshold(registry *metrics.Registry, threshold float64) *Map {
	if registry == nil {
		return m
	}

	if m.cache == nil {
		m.cache = map[string]*cacheEntry{}
	}

	m.pressureGauge = registry.NewBPFMapPressureGauge(m.NonPrefixedName(), threshold)

	return m
}

// WithPressureMetric enables tracking and reporting of this map pressure with
// threshold 0.
func (m *Map) WithPressureMetric(registry *metrics.Registry) *Map {
	return m.WithPressureMetricThreshold(registry, 0.0)
}

// UpdatePressureMetricWithSize updates map pressure metric using the given map size.
func (m *Map) UpdatePressureMetricWithSize(size int32) {
	if m.pressureGauge == nil {
		return
	}

	if !metrics.BPFMapPressure {
		if !m.withValueCache {
			m.cache = nil
		}
		m.pressureGauge = nil
		return
	}

	pvalue := float64(size) / float64(m.MaxEntries())
	m.pressureGauge.Set(pvalue)
}

func (m *Map) updatePressureMetric() {
	if m.spec != nil && m.spec.Type == ebpf.LRUHash {
		return
	}
	m.UpdatePressureMetricWithSize(int32(len(m.cache)))
}

func (m *Map) FD() int {
	return m.m.FD()
}

// Name returns the basename of this map.
func (m *Map) Name() string {
	return m.name
}

// Path returns the path to this map on the filesystem.
func (m *Map) Path() (string, error) {
	if err := m.setPathIfUnset(); err != nil {
		return "", err
	}

	return m.path, nil
}

// Unpin attempts to unpin (remove) the map from the filesystem.
func (m *Map) Unpin() error {
	path, err := m.Path()
	if err != nil {
		return err
	}

	return os.RemoveAll(path)
}

// UnpinIfExists tries to unpin (remove) the map only if it exists.
func (m *Map) UnpinIfExists() error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if !found {
		return nil
	}

	return m.Unpin()
}

func (m *Map) controllerName() string {
	return fmt.Sprintf("bpf-map-sync-%s", m.name)
}

// OpenMap opens the map at pinPath.
func OpenMap(pinPath string, key MapKey, value MapValue) (*Map, error) {
	if !path.IsAbs(pinPath) {
		return nil, fmt.Errorf("pinPath must be absolute: %s", pinPath)
	}

	em, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return nil, err
	}

	defaultSlogLogger := logging.DefaultSlogLogger

	logger := defaultSlogLogger.With(
		logfields.BPFMapPath, pinPath,
		logfields.BPFMapName, path.Base(pinPath),
	)
	m := &Map{
		Logger: logger,
		m:      em,
		name:   path.Base(pinPath),
		path:   pinPath,
		key:    key,
		value:  value,
	}

	m.updateMetrics()
	registerMap(logger, pinPath, m)

	return m, nil
}

func (m *Map) setPathIfUnset() error {
	if m.path == "" {
		if m.name == "" {
			return fmt.Errorf("either path or name must be set")
		}

		m.path = MapPath(m.Logger, m.name)
	}

	return nil
}

// Recreate removes any pin at the Map's pin path, recreates and re-pins it.
func (m *Map) Recreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.m != nil {
		return fmt.Errorf("map already open: %s", m.name)
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	if err := os.Remove(m.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing pinned map %s: %w", m.name, err)
	}

	m.Logger.Info(
		"Removed map pin, recreating and re-pinning map",
	)

	return m.openOrCreate(true)
}

// IsOpen returns true if the map has been opened.
func (m *Map) IsOpen() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.m != nil
}

// OpenOrCreate attempts to open the Map, or if it does not yet exist, create
// the Map.
func (m *Map) OpenOrCreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(true)
}

// CreateUnpinned creates the map without pinning it to the file system.
func (m *Map) CreateUnpinned() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(false)
}

// Create is similar to OpenOrCreate, but closes the map after creating or
// opening it.
func (m *Map) Create() error {
	if err := m.OpenOrCreate(); err != nil {
		return err
	}
	return m.Close()
}

func (m *Map) openOrCreate(pin bool) error {
	if m.m != nil {
		return nil
	}

	if m.spec == nil {
		return fmt.Errorf("attempted to create map %s without MapSpec", m.name)
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	m.spec.Flags |= GetMapMemoryFlags(m.spec.Type)

	if m.spec.InnerMap != nil {
		m.spec.InnerMap.Flags |= GetMapMemoryFlags(m.spec.InnerMap.Type)
	}

	if pin {
		m.spec.Pinning = ebpf.PinByName
	}

	em, err := OpenOrCreateMap(m.Logger, m.spec, path.Dir(m.path))
	if err != nil {
		return err
	}

	// Consume the MapSpec.
	m.spec = nil

	// Retain the Map.
	m.m = em

	m.updateMetrics()
	registerMap(m.Logger, m.path, m)

	return nil
}

// Open opens the BPF map.
func (m *Map) Open() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.open()
}

func (m *Map) open() error {
	if m.m != nil {
		return nil
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	em, err := ebpf.LoadPinnedMap(m.path, nil)
	if err != nil {
		return fmt.Errorf("loading pinned map %s: %w", m.path, err)
	}

	m.m = em

	m.updateMetrics()
	registerMap(m.Logger, m.path, m)

	return nil
}

func (m *Map) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.enableSync {
		mapControllers.RemoveController(m.controllerName())
	}

	if m.m != nil {
		m.m.Close()
		m.m = nil
	}

	unregisterMap(m.Logger, m.path, m)

	return nil
}

func (m *Map) NextKey(key, nextKeyOut any) error {
	return m.m.NextKey(key, nextKeyOut)
}

type DumpCallback func(key MapKey, value MapValue)

// DumpWithCallback iterates over the Map and calls the given DumpCallback for
// each map entry.
func (m *Map) DumpWithCallback(cb DumpCallback) error {
	if cb == nil {
		return errors.New("empty callback")
	}

	if err := m.Open(); err != nil {
		return err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	mk := m.key.New()
	mv := m.value.New()

	i := m.m.Iterate()
	for i.Next(mk, mv) {
		cb(mk, mv)

		mk = m.key.New()
		mv = m.value.New()
	}

	return i.Err()
}

// DumpPerCPUCallback is called by DumpPerCPUWithCallback with the map key and
// the slice of all values from all CPUs.
type DumpPerCPUCallback func(key MapKey, values any)

// DumpPerCPUWithCallback iterates over the Map and calls the given
// DumpPerCPUCallback for each map entry.
func (m *Map) DumpPerCPUWithCallback(cb DumpPerCPUCallback) error {
	if cb == nil {
		return errors.New("empty callback")
	}

	if !m.hasPerCPUValue() {
		return fmt.Errorf("map %s is not a per-CPU map", m.name)
	}

	v, ok := m.value.(MapPerCPUValue)
	if !ok {
		return fmt.Errorf("map %s value type does not implement MapPerCPUValue", m.name)
	}

	if err := m.Open(); err != nil {
		return err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	mk := m.key.New()
	mv := v.NewSlice()

	i := m.m.Iterate()
	for i.Next(mk, mv) {
		cb(mk, mv)

		mk = m.key.New()
		mv = v.NewSlice()
	}

	return i.Err()
}

// DumpWithCallbackIfExists is similar to DumpWithCallback, but returns earlier
// if the given map does not exist.
func (m *Map) DumpWithCallbackIfExists(cb DumpCallback) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.DumpWithCallback(cb)
	}

	return nil
}

// DumpReliablyWithCallback performs a reliable dump of the BPF map, handling
// concurrent deletions gracefully.
func (m *Map) DumpReliablyWithCallback(cb DumpCallback, stats *DumpStats) error {
	if cb == nil {
		return errors.New("empty callback")
	}

	if stats == nil {
		return errors.New("stats is nil")
	}

	var (
		prevKey    = m.key.New()
		currentKey = m.key.New()
		nextKey    = m.key.New()
		value      = m.value.New()

		prevKeyValid = false
	)

	stats.start()
	defer stats.finish()

	if err := m.Open(); err != nil {
		return err
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	if m.m == nil {
		return errors.New("map is closed")
	}

	if err := m.NextKey(nil, currentKey); err != nil {
		stats.Lookup = 1
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			stats.Completed = true
			return nil
		}
	}

	maxLookup := stats.MaxEntries * 4

	for stats.Lookup = 1; stats.Lookup <= maxLookup; stats.Lookup++ {
		nextKeyErr := m.NextKey(currentKey, nextKey)

		if err := m.m.Lookup(currentKey, value); err != nil {
			stats.LookupFailed++
			if prevKeyValid {
				currentKey = prevKey
				prevKeyValid = false
				stats.KeyFallback++
			} else {
				currentKey = nextKey
				nextKey = m.key.New()
				stats.Interrupted++
			}
			continue
		}

		cb(currentKey, value)

		if nextKeyErr != nil {
			if errors.Is(nextKeyErr, ebpf.ErrKeyNotExist) {
				stats.Completed = true
				return nil
			}
			return nextKeyErr
		}

		prevKey = currentKey
		currentKey = nextKey
		nextKey = m.key.New()
		prevKeyValid = true
	}

	return ErrMaxLookup
}

// Dump returns the map contents as a map[string][]string.
func (m *Map) Dump(hash map[string][]string) error {
	callback := func(key MapKey, value MapValue) {
		hash[key.String()] = append(hash[key.String()], value.String())
	}

	if err := m.DumpWithCallback(callback); err != nil {
		return err
	}

	return nil
}

// DumpIfExists dumps the contents of the map if it exists.
func (m *Map) DumpIfExists(hash map[string][]string) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.Dump(hash)
	}

	return nil
}

func (m *Map) Lookup(key MapKey) (MapValue, error) {
	if err := m.Open(); err != nil {
		return nil, err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	value := m.value.New()
	err := m.m.Lookup(key, value)

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (m *Map) Update(key MapKey, value MapValue) error {
	var err error

	m.lock.Lock()
	defer m.lock.Unlock()

	defer func() {
		desiredAction := OK
		if err != nil {
			desiredAction = Insert
		}
		entry := &cacheEntry{
			Key:           key,
			Value:         value,
			DesiredAction: desiredAction,
			LastError:     err,
		}
		m.addToEventsLocked(MapUpdate, *entry)

		if m.cache == nil {
			return
		}

		if m.withValueCache {
			if err != nil {
				m.scheduleErrorResolver()
			}
			m.cache[key.String()] = &cacheEntry{
				Key:           key,
				Value:         value,
				DesiredAction: desiredAction,
				LastError:     err,
			}
			m.updatePressureMetric()
		} else if err == nil {
			m.cache[key.String()] = nil
			m.updatePressureMetric()
		}
	}()

	if err = m.open(); err != nil {
		return err
	}

	err = m.m.Update(key, value, ebpf.UpdateAny)

	if metrics.BPFMapOps.IsEnabled() {
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
	}

	if err != nil {
		return fmt.Errorf("update map %s: %w", m.Name(), err)
	}

	return nil
}

// deleteMapEvent is run at every delete map event.
func (m *Map) deleteMapEvent(key MapKey, err error) {
	m.addToEventsLocked(MapDelete, cacheEntry{
		Key:           key,
		DesiredAction: Delete,
		LastError:     err,
	})
	m.deleteCacheEntry(key, err)
}

func (m *Map) deleteAllMapEvent() {
	m.addToEventsLocked(MapDeleteAll, cacheEntry{})
}

func (m *Map) deleteCacheEntry(key MapKey, err error) {
	if m.cache == nil {
		return
	}

	k := key.String()
	if err == nil {
		delete(m.cache, k)
	} else if !m.withValueCache {
		return
	} else {
		entry, ok := m.cache[k]
		if !ok {
			m.cache[k] = &cacheEntry{
				Key: key,
			}
			entry = m.cache[k]
		}

		entry.DesiredAction = Delete
		entry.LastError = err
		m.scheduleErrorResolver()
	}
}

func (m *Map) delete(key MapKey, ignoreMissing bool) (_ bool, err error) {
	defer func() {
		m.deleteMapEvent(key, err)
		if err != nil {
			m.updatePressureMetric()
		}
	}()

	if err = m.open(); err != nil {
		return false, err
	}

	err = m.m.Delete(key)

	if errors.Is(err, ebpf.ErrKeyNotExist) && ignoreMissing {
		return false, nil
	}

	if metrics.BPFMapOps.IsEnabled() {
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Error2Outcome(err)).Inc()
	}

	if err != nil {
		return false, fmt.Errorf("unable to delete element %s from map %s: %w", key, m.name, err)
	}

	return true, nil
}

// SilentDelete deletes the map entry corresponding to the given key.
// If a map entry is not found this returns (false, nil).
func (m *Map) SilentDelete(key MapKey) (deleted bool, err error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.delete(key, true)
}

// Delete deletes the map entry corresponding to the given key.
func (m *Map) Delete(key MapKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, err := m.delete(key, false)
	return err
}

// DeleteLocked deletes the map entry for the given key.
// Assumes m.lock is already acquired.
func (m *Map) DeleteLocked(key MapKey) error {
	_, err := m.delete(key, false)
	return err
}

// DeleteAll deletes all entries of a map by traversing the map.
func (m *Map) DeleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()
	defer m.updatePressureMetric()
	m.Logger.Debug("deleting all entries in map")

	if m.withValueCache {
		for _, entry := range m.cache {
			entry.DesiredAction = Delete
			entry.LastError = fmt.Errorf("deletion pending")
		}
	}

	if err := m.open(); err != nil {
		return err
	}

	mk := m.key.New()
	mv := make([]byte, m.ValueSize())

	defer m.deleteAllMapEvent()

	i := m.m.Iterate()
	for i.Next(mk, &mv) {
		err := m.m.Delete(mk)

		m.deleteCacheEntry(mk, err)

		if err != nil {
			return err
		}
	}

	err := i.Err()
	if err != nil {
		m.Logger.Warn(
			"Unable to correlate iteration key with cache entry. Inconsistent cache.",
			logfields.Error, err,
			logfields.Key, mk,
		)
	}

	return err
}

func (m *Map) ClearAll() error {
	if m.eventsBufferEnabled || m.withValueCache {
		return fmt.Errorf("clear map: events buffer and value cache are not supported")
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	defer m.updatePressureMetric()

	if err := m.open(); err != nil {
		return err
	}

	mk := m.key.New()
	var mv any
	if m.hasPerCPUValue() {
		mv = m.value.(MapPerCPUValue).NewSlice()
	} else {
		mv = m.value.New()
	}
	empty := reflect.Indirect(reflect.ValueOf(mv)).Interface()

	i := m.m.Iterate()
	for i.Next(mk, mv) {
		err := m.m.Update(mk, empty, ebpf.UpdateAny)

		if metrics.BPFMapOps.IsEnabled() {
			metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
		}

		if err != nil {
			return err
		}
	}

	return i.Err()
}

// GetModel returns a BPF map in the representation served via the API
func (m *Map) GetModel() *models.BPFMap {
	mapModel := &models.BPFMap{
		Path: m.path,
	}

	mapModel.Cache = make([]*models.BPFMapEntry, 0, len(m.cache))
	if m.withValueCache {
		m.lock.RLock()
		defer m.lock.RUnlock()
		for k, entry := range m.cache {
			model := &models.BPFMapEntry{
				Key:           k,
				DesiredAction: entry.DesiredAction.String(),
			}

			if entry.LastError != nil {
				model.LastError = entry.LastError.Error()
			}

			if entry.Value != nil {
				model.Value = entry.Value.String()
			}
			mapModel.Cache = append(mapModel.Cache, model)
		}
		return mapModel
	}

	stats := NewDumpStats(m)
	filterCallback := func(key MapKey, value MapValue) {
		mapModel.Cache = append(mapModel.Cache, &models.BPFMapEntry{
			Key:   key.String(),
			Value: value.String(),
		})
	}

	m.DumpReliablyWithCallback(filterCallback, stats)
	return mapModel
}

func (m *Map) addToEventsLocked(action Action, entry cacheEntry) {
	if !m.eventsBufferEnabled {
		return
	}
	m.events.add(&Event{
		action:     action,
		Timestamp:  time.Now(),
		cacheEntry: entry,
	})
}

// resolveErrors resolves discrepancies between cache and BPF map.
func (m *Map) resolveErrors(ctx context.Context) error {
	started := time.Now()

	m.lock.Lock()
	defer m.lock.Unlock()

	if m.cache == nil {
		return nil
	}

	if !m.outstandingErrors {
		return nil
	}

	outstanding := 0
	for _, e := range m.cache {
		switch e.DesiredAction {
		case Insert, Delete:
			outstanding++
		}
	}

	if outstanding == 0 {
		m.outstandingErrors = false
		return nil
	}

	if err := m.open(); err != nil {
		return err
	}

	m.Logger.Debug(
		"Starting periodic BPF map error resolver",
		logfields.Remaining, outstanding,
	)

	resolved := 0
	scanned := 0
	nerr := 0
	for k, e := range m.cache {
		scanned++

		switch e.DesiredAction {
		case OK:
		case Insert:
			err := m.m.Update(e.Key, e.Value, ebpf.UpdateAny)
			if metrics.BPFMapOps.IsEnabled() {
				metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
			}
			if err == nil {
				e.DesiredAction = OK
				e.LastError = nil
				resolved++
				outstanding--
			} else {
				e.LastError = err
				nerr++
			}
			m.cache[k] = e
			m.addToEventsLocked(MapUpdate, *e)
		case Delete:
			err := m.m.Delete(e.Key)
			if metrics.BPFMapOps.IsEnabled() {
				metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Error2Outcome(err)).Inc()
			}
			if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
				delete(m.cache, k)
				resolved++
				outstanding--
			} else {
				e.LastError = err
				nerr++
				m.cache[k] = e
			}

			m.addToEventsLocked(MapDelete, *e)
		}

		if nerr > maxSyncErrors {
			break
		}
	}

	m.updatePressureMetric()

	m.Logger.Debug(
		"BPF map error resolver completed",
		logfields.Remaining, outstanding,
		logfields.Resolved, resolved,
		logfields.Scanned, scanned,
		logfields.Duration, time.Since(started),
	)

	m.outstandingErrors = outstanding > 0
	if m.outstandingErrors {
		return fmt.Errorf("%d map sync errors", outstanding)
	}

	return nil
}

func (m *Map) exist() (bool, error) {
	path, err := m.Path()
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(path); err == nil {
		return true, nil
	}

	return false, nil
}

// BatchLookup returns the count of elements in the map by dumping the map
// using batch lookup.
func (m *Map) BatchLookup(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error) {
	return m.m.BatchLookup(cursor, keysOut, valuesOut, opts)
}

// GetMtime returns monotonic time that can be used to compare
// values with ktime_get_ns() BPF helper. On Windows, this returns
// the system uptime in nanoseconds.
func GetMtime() (uint64, error) {
	// On Windows, use time.Since epoch as an approximation.
	// The actual kernel timestamp is not directly accessible on Windows.
	return uint64(time.Since(time.Time{}).Nanoseconds()), nil
}

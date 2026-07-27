// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ebpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
)

// Map represents an eBPF map. On platforms without the eBPF runtime it is
// backed by an in-memory key/value store (see pkg/bpf) so that the agent's
// control plane remains runnable. No datapath program ever consumes it.
type Map struct {
	logger *slog.Logger
	lock   lock.RWMutex
	*bpf.InMemoryMap

	spec *MapSpec
	path string
}

// NewMap creates a new Map object.
func NewMap(logger *slog.Logger, spec *MapSpec) *Map {
	return &Map{
		logger: logger,
		spec:   spec,
	}
}

// LoadRegisterMap loads the specified map from its (emulated) pin path and
// registers its handle in the package-global map register.
func LoadRegisterMap(logger *slog.Logger, mapName string) (*Map, error) {
	path := bpf.MapPath(logger, mapName)

	m, err := LoadPinnedMap(logger, path)
	if err != nil {
		return nil, err
	}

	registerMap(m)

	return m, nil
}

// LoadPinnedMap returns the in-memory map registered at fileName, creating an
// empty one when none exists.
func LoadPinnedMap(logger *slog.Logger, fileName string) (*Map, error) {
	return &Map{
		logger:      logger,
		InMemoryMap: bpf.LoadInMemoryMap(fileName, nil),
		path:        fileName,
	}, nil
}

// MapFromID is not supported without the eBPF runtime, as there are no kernel
// map IDs to resolve.
func MapFromID(logger *slog.Logger, id int) (*Map, error) {
	return nil, fmt.Errorf("looking up BPF maps by ID is not supported on this platform")
}

// OpenOrCreate creates the in-memory map identified by the spec.
func (m *Map) OpenOrCreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.InMemoryMap != nil {
		return nil
	}

	if m.spec == nil {
		return fmt.Errorf("cannot create map: nil map spec")
	}

	m.spec.Flags |= bpf.GetMapMemoryFlags(m.spec.Type)
	path := bpf.MapPath(m.logger, m.spec.Name)

	m.InMemoryMap = bpf.OpenOrCreateInMemoryMap(path, m.spec)
	m.path = path

	registerMap(m)
	metrics.UpdateMapCapacity(m.spec.Name, m.spec.MaxEntries)
	return nil
}

// IterateWithCallback iterates through all the keys/values of a map, passing
// each key/value pair to the cb callback.
func (m *Map) IterateWithCallback(key, value any, cb IterateCallback) error {
	if err := m.OpenOrCreate(); err != nil {
		return err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	entries := m.Iterate()
	for entries.Next(key, value) {
		cb(key, value)
	}

	return entries.Err()
}

// GetModel returns a BPF map in the representation served via the API.
func (m *Map) GetModel() *models.BPFMap {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return &models.BPFMap{
		Path: m.path,
	}
}

func (m *Map) IsEmpty() bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	var key, value any
	return !m.Iterate().Next(key, value)
}

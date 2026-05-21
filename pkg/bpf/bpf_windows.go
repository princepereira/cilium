// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sync/atomic"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	preAllocateMapSetting uint32 = 0
	noCommonLRUMapSetting uint32 = 0
)

// EnableMapPreAllocation enables BPF map pre-allocation on map types that
// support it. On Windows this is a no-op as map memory is managed by the
// CNC API / eBPF for Windows.
func EnableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 0)
}

// DisableMapPreAllocation disables BPF map pre-allocation as a default
// setting. On Windows this is a no-op.
func DisableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 0)
}

// EnableMapDistributedLRU enables the LRU map no-common-LRU feature.
// On Windows this is a no-op.
func EnableMapDistributedLRU() {
	atomic.StoreUint32(&noCommonLRUMapSetting, 0)
}

// DisableMapDistributedLRU disables the LRU map no-common-LRU feature.
// On Windows this is a no-op.
func DisableMapDistributedLRU() {
	atomic.StoreUint32(&noCommonLRUMapSetting, 0)
}

// GetMapMemoryFlags returns relevant map memory allocation flags.
// On Windows, no flags are needed as map memory is managed by the
// eBPF for Windows runtime.
func GetMapMemoryFlags(t ebpf.MapType) uint32 {
	return 0
}

// createMap wraps a call to ebpf.NewMapWithOptions on Windows.
func createMap(spec *ebpf.MapSpec, opts *ebpf.MapOptions) (*ebpf.Map, error) {
	if opts == nil {
		opts = &ebpf.MapOptions{}
	}

	return ebpf.NewMapWithOptions(spec, *opts)
}

// OpenOrCreateMap attempts to load the pinned map at "pinDir/<spec.Name>" if
// the spec is marked as Pinned. Any parent directories of pinDir are
// automatically created. Any pinned maps incompatible with the given spec are
// removed and recreated.
//
// If spec.Pinned is 0, a new Map is always created.
func OpenOrCreateMap(logger *slog.Logger, spec *ebpf.MapSpec, pinDir string) (*ebpf.Map, error) {
	var opts ebpf.MapOptions
	if spec.Pinning != 0 {
		if pinDir == "" {
			return nil, errors.New("cannot pin map to empty pinDir")
		}
		if spec.Name == "" {
			return nil, errors.New("cannot load unnamed map from pin")
		}

		if err := MkdirBPF(pinDir); err != nil {
			return nil, fmt.Errorf("creating map base pinning directory: %w", err)
		}

		opts.PinPath = pinDir
	}

	m, err := createMap(spec, &opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Found incompatible map. Open the pin again to find out why.
		m, err := ebpf.LoadPinnedMap(path.Join(pinDir, spec.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("open pin of incompatible map: %w", err)
		}
		defer m.Close()

		logger.Info(
			"Unpinning map with incompatible properties",
			logfields.Path, path.Join(pinDir, spec.Name),
			logfields.Old, []any{
				logfields.Type, m.Type(),
				logfields.KeySize, m.KeySize(),
				logfields.ValueSize, m.ValueSize(),
				logfields.MaxEntries, m.MaxEntries(),
				logfields.Flags, m.Flags(),
			},
			logfields.New, []any{
				logfields.Type, spec.Type,
				logfields.KeySize, spec.KeySize,
				logfields.ValueSize, spec.ValueSize,
				logfields.MaxEntries, spec.MaxEntries,
				logfields.Flags, spec.Flags,
			},
		)

		// Existing map incompatible with spec. Unpin so it can be recreated.
		if err := m.Unpin(); err != nil {
			return nil, err
		}

		return createMap(spec, &opts)
	}

	return m, err
}


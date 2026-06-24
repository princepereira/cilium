// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"

	"github.com/cilium/ebpf"
)

var (
	preAllocateMapSetting uint32 = 0
	noCommonLRUMapSetting uint32 = 0
)

// EnableMapPreAllocation is a no-op on Windows.
func EnableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 0)
}

// DisableMapPreAllocation is a no-op on Windows.
func DisableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 1)
}

// EnableMapDistributedLRU is a no-op on Windows.
func EnableMapDistributedLRU() {
	atomic.StoreUint32(&noCommonLRUMapSetting, 1)
}

// DisableMapDistributedLRU is a no-op on Windows.
func DisableMapDistributedLRU() {
	atomic.StoreUint32(&noCommonLRUMapSetting, 0)
}

// GetMapMemoryFlags returns 0 on Windows as eBPF maps are not used.
func GetMapMemoryFlags(t ebpf.MapType) uint32 {
	return 0
}

// GetMtime returns a monotonic timestamp (stub on Windows).
func GetMtime() (uint64, error) {
	return 0, nil
}

// TCGlobalsPath returns the path for BPF TC globals (stub on Windows).
func TCGlobalsPath() string {
	return filepath.Join(`C:\ProgramData\cilium\bpf`, "tc", "globals")
}

// MapPath returns the path for a named BPF map (stub on Windows).
func MapPath(_ *slog.Logger, name string) string {
	return filepath.Join(TCGlobalsPath(), name)
}

// LocalMapPath returns the path for a per-endpoint BPF map (stub on Windows).
func LocalMapPath(_ *slog.Logger, name string, id uint16) string {
	return filepath.Join(TCGlobalsPath(), fmt.Sprintf("%s%05d", name, id))
}

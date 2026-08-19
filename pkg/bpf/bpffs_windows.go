// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"log/slog"
	"sync"
)

var mountOnce sync.Once

// EbpfGlobalPinPrefix mirrors DEFAULT_MAP_PIN_PATH_PREFIX in eBPF-for-Windows'
// cilium_maps.h. eBPF-for-Windows pins every Cilium map in the driver-owned
// "/ebpf/global/" namespace using forward-slash paths, NOT a bpffs mount. The
// datapath programs and the winebpfmap tooling both pin here, so the agent must
// use the same prefix for its maps to resolve to the same pinned objects.
const EbpfGlobalPinPrefix = "/ebpf/global"

// agentMapPath returns the efw pin path for a map name: /ebpf/global/<name>.
// It deliberately uses forward slashes (path, not filepath): efw pin paths live
// in a driver-owned namespace and must match the datapath's pins exactly.
// filepath.Join would emit backslashes on Windows, producing a distinct,
// unshared pin that the datapath never reads.
func agentMapPath(name string) string {
	return EbpfGlobalPinPrefix + "/" + name
}

// tcPathFromMountInfo returns the efw pin path for the given map name. On
// Windows there is no bpffs mount to inspect; every pin lives under
// /ebpf/global/.
func tcPathFromMountInfo(logger *slog.Logger, name string) string {
	return agentMapPath(name)
}

// CheckOrMountFS is a no-op on Windows. eBPF-for-Windows has no bpffs mount to
// manage; the driver owns the pin namespace. It still sets the pin root when a
// custom one is provided.
func CheckOrMountFS(logger *slog.Logger, bpfRoot string) {
	mountOnce.Do(func() {
		if bpfRoot != "" {
			setBPFFSRoot(bpfRoot)
		}
	})
}

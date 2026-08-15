// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/pkg/defaults"
)

var mountOnce sync.Once

// tcPathFromMountInfo returns the legacy tc/globals pin path for the given map
// name. On Windows there is no bpffs mount to inspect, so the path is derived
// directly from the configured pin root.
func tcPathFromMountInfo(logger *slog.Logger, name string) string {
	return filepath.Join(bpffsRoot, defaults.TCGlobalsPath, name)
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

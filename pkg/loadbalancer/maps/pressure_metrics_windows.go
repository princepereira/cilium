// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"log/slog"

	"github.com/cilium/hive/cell"
)

type pressureMetricsParams struct {
	cell.In

	Log *slog.Logger
}

// registerPressureMetricsReporter is a no-op on Windows. BPF map pressure
// metrics rely on direct eBPF map introspection (BatchCount over the pinned
// maps), which is not available when the datapath is programmed through the
// CNC API. See lbmaps_windows.go.
func registerPressureMetricsReporter(p pressureMetricsParams) {
	p.Log.Debug("BPF map pressure metrics reporter not implemented on Windows")
}

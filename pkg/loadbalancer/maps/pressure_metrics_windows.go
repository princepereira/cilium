// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import "github.com/cilium/hive/cell"

// pressureMetricsParams is the Windows stub — on Linux this struct carries
// BPF map and metrics dependencies. On Windows there are no BPF maps so this
// is empty and registerPressureMetricsReporter is a no-op.
type pressureMetricsParams struct {
	cell.In
}

// registerPressureMetricsReporter is a no-op on Windows.
// BPF map pressure metrics only apply to the Linux eBPF data plane.
func registerPressureMetricsReporter(_ pressureMetricsParams) {}

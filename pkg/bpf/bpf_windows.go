// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bpf

import (
	"log/slog"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

// createMap wraps a call to ebpf.NewMapWithOptions while measuring syscall duration.
func createMap(spec *ebpf.MapSpec, opts *ebpf.MapOptions) (*ebpf.Map, error) {
	if opts == nil {
		opts = &ebpf.MapOptions{}
	}

	var duration *spanstat.SpanStat
	if metrics.BPFSyscallDuration.IsEnabled() {
		duration = spanstat.Start()
	}

	m, err := ebpf.NewMapWithOptions(spec, *opts)

	if metrics.BPFSyscallDuration.IsEnabled() {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpCreate, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	return m, err
}

// OpenOrCreateMap creates a new map. Pinning to a BPF filesystem is a
// Linux-only concept, so pinDir is ignored on other platforms.
func OpenOrCreateMap(logger *slog.Logger, spec *ebpf.MapSpec, pinDir string) (*ebpf.Map, error) {
	return createMap(spec, nil)
}

// GetMtime returns a monotonic-ish timestamp in nanoseconds. On non-Linux
// platforms the BPF ktime helper is unavailable, so this is only a best-effort
// value derived from the Go runtime clock.
func GetMtime() (uint64, error) {
	return uint64(time.Now().UnixNano()), nil
}

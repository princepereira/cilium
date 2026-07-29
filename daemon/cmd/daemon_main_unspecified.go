// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cmd

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/option"
)

// checkBPFTemplateDir is a no-op on non-Linux platforms. The eBPF datapath is
// not available, so no BPF template/source directory is required.
func checkBPFTemplateDir(_ *slog.Logger) error {
	return nil
}

// createBPFHeaderFiles is a no-op on non-Linux platforms. Kernel feature
// probing and BPF header generation are Linux-only concepts.
func createBPFHeaderFiles(_ *slog.Logger) error {
	return nil
}

// mountBPFFilesystems is a no-op on non-Linux platforms. There is no BPF or
// cgroup v2 filesystem to mount.
func mountBPFFilesystems(_ *slog.Logger) {
}

// initClockSourceOption selects a portable clock source on non-Linux platforms.
// The jiffies-based BPF clock probe relies on kernel internals that are not
// available outside Linux, so it is disabled and the ktime clock source is used.
func initClockSourceOption(_ *slog.Logger) {
	option.Config.ClockSource = option.ClockSourceKtime
	option.Config.EnableBPFClockProbe = false
}

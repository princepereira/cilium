// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cmd

import "log/slog"

// removeMemlock is a no-op on non-Linux platforms, which do not use the
// RLIMIT_MEMLOCK-guarded BPF resources.
func removeMemlock(scopedLog *slog.Logger) {}

// checkBPFTemplates is a no-op on non-Linux platforms, which do not compile or
// load the BPF datapath.
func checkBPFTemplates(scopedLog *slog.Logger) {}

// mountFilesystems is a no-op on non-Linux platforms, which have neither a BPF
// filesystem nor cgroup v2 to mount.
func mountFilesystems(logger *slog.Logger) {}

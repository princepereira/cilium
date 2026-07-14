// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// removeMemlock raises the RLIMIT_MEMLOCK resource limit to infinity, which is
// required before creating any BPF resources on Linux.
func removeMemlock(scopedLog *slog.Logger) {
	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Fatal(scopedLog, "unable to set memory resource limits", logfields.Error, err)
	}
}

// checkBPFTemplates ensures the BPF template directory is present and generates
// the feature-macro header files used when compiling the datapath.
func checkBPFTemplates(scopedLog *slog.Logger) {
	if _, err := os.Stat(option.Config.BpfDir); os.IsNotExist(err) {
		logging.Fatal(scopedLog, "BPF template directory: NOT OK. Please run 'make install-bpf'", logfields.Error, err)
	}

	if err := probes.CreateHeaderFiles(filepath.Join(option.Config.BpfDir, "include/bpf"), probes.ExecuteHeaderProbes(scopedLog)); err != nil {
		logging.Fatal(scopedLog, "failed to create header files with feature macros", logfields.Error, err)
	}
}

// mountFilesystems mounts the BPF and cgroup v2 filesystems that the datapath
// relies on.
func mountFilesystems(logger *slog.Logger) {
	bpf.CheckOrMountFS(logger, option.Config.BPFRoot)
	cgroups.CheckOrMountCgrpFS(logger, option.Config.CGroupRoot)
}

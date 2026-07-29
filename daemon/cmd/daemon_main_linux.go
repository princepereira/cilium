// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// checkBPFTemplateDir verifies that the BPF template/source directory installed
// by 'make install-bpf' is present. The datapath loader needs it to compile
// per-endpoint BPF programs.
func checkBPFTemplateDir(_ *slog.Logger) error {
	if _, err := os.Stat(option.Config.BpfDir); os.IsNotExist(err) {
		return err
	}
	return nil
}

// createBPFHeaderFiles runs the kernel feature probes and writes the resulting
// feature macro header files consumed by the BPF datapath compilation.
func createBPFHeaderFiles(scopedLog *slog.Logger) error {
	return probes.CreateHeaderFiles(filepath.Join(option.Config.BpfDir, "include/bpf"), probes.ExecuteHeaderProbes(scopedLog))
}

// mountBPFFilesystems ensures the BPF and cgroup v2 filesystems are mounted at
// their configured locations. The standard operation is to mount the BPF
// filesystem to the standard location (/sys/fs/bpf). The user may choose to
// specify the path to an already mounted filesystem instead. This is useful if
// the daemon is being run inside a namespace and the BPF filesystem is mapped
// into the slave namespace.
func mountBPFFilesystems(logger *slog.Logger) {
	bpf.CheckOrMountFS(logger, option.Config.BPFRoot)
	cgroups.CheckOrMountCgrpFS(logger, option.Config.CGroupRoot)
}

func initClockSourceOption(logger *slog.Logger) {
	option.Config.ClockSource = option.ClockSourceKtime
	hz, err := probes.KernelHZ()
	if err != nil {
		logger.Info(
			fmt.Sprintf("Auto-disabling %q feature since KERNEL_HZ cannot be determined", option.EnableBPFClockProbe),
			logfields.Error, err,
		)
		option.Config.EnableBPFClockProbe = false
	} else {
		option.Config.KernelHz = int(hz)
	}

	if option.Config.EnableBPFClockProbe {
		t, err := probes.Jiffies()
		if err == nil && t > 0 {
			option.Config.ClockSource = option.ClockSourceJiffies
		} else {
			logger.Warn(
				fmt.Sprintf("Auto-disabling %q feature since kernel doesn't expose jiffies", option.EnableBPFClockProbe),
				logfields.Error, err,
			)
			option.Config.EnableBPFClockProbe = false
		}
	}
}

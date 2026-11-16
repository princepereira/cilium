// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// verifyBPFTemplateDir ensures the compiled BPF datapath template directory is
// present and generates the feature-macro header files. On Linux the datapath
// programs are compiled from these C templates, so a missing directory is fatal.
func verifyBPFTemplateDir(scopedLog *slog.Logger) {
	if _, err := os.Stat(option.Config.BpfDir); os.IsNotExist(err) {
		logging.Fatal(scopedLog, "BPF template directory: NOT OK. Please run 'make install-bpf'", logfields.Error, err)
	}

	if err := probes.CreateHeaderFiles(filepath.Join(option.Config.BpfDir, "include/bpf"), probes.ExecuteHeaderProbes(scopedLog)); err != nil {
		logging.Fatal(scopedLog, "failed to create header files with feature macros", logfields.Error, err)
	}
}

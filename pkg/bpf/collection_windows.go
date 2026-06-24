// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
)

// PinReplace matches CILIUM_PIN_REPLACE.
const PinReplace = ebpf.PinType(1 << 4)

// CollectionOptions holds options for loading a BPF collection.
type CollectionOptions struct {
	ebpf.CollectionOptions

	// Constants sets the values of BPF C runtime configurables.
	Constants any

	// ConfigDumpPath is the path to dump the config to.
	ConfigDumpPath string
}

// LoadAndAssign loads a BPF collection and assigns maps/programs to the target.
// Stub on Windows - eBPF programs are not loaded.
func LoadAndAssign(logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *CollectionOptions) (func() error, error) {
	return func() error { return nil }, fmt.Errorf("BPF program loading not supported on Windows")
}

// LoadCollection loads a BPF collection. Stub on Windows.
func LoadCollection(logger *slog.Logger, spec *ebpf.CollectionSpec, opts *CollectionOptions) (*ebpf.Collection, func() error, error) {
	return nil, func() error { return nil }, fmt.Errorf("BPF collection loading not supported on Windows")
}

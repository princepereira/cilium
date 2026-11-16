// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package socketlb

import (
	"log/slog"

	"github.com/cilium/ebpf"
)

// attachCgroup is a no-op on non-Linux platforms, where cgroup-based BPF
// program attachment is not supported.
func attachCgroup(logger *slog.Logger, spec *ebpf.Collection, name, cgroupRoot, pinPath string) error {
	return nil
}

// detachCgroup is a no-op on non-Linux platforms, where cgroup-based BPF
// program attachment is not supported.
func detachCgroup(logger *slog.Logger, name, cgroupRoot, pinPath string) error {
	return nil
}

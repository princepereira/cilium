// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package socketlb

import (
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
)

func attachCgroup(logger *slog.Logger, spec *ebpf.Collection, name, cgroupRoot, pinPath string) error {
	return fmt.Errorf("socketlb cgroup attach is not supported on this platform")
}

func detachCgroup(logger *slog.Logger, name, cgroupRoot, pinPath string) error {
	return fmt.Errorf("socketlb cgroup detach is not supported on this platform")
}

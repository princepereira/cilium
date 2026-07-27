// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package socketlb

import (
	"errors"
	"log/slog"

	"github.com/cilium/ebpf"
)

var errNotSupported = errors.New("socketlb cgroup attach is not supported on this platform")

// attachCgroup is not supported on non-Linux platforms.
func attachCgroup(logger *slog.Logger, spec *ebpf.Collection, name, cgroupRoot, pinPath string) error {
	return errNotSupported
}

// detachCgroup is not supported on non-Linux platforms.
func detachCgroup(logger *slog.Logger, name, cgroupRoot, pinPath string) error {
	return errNotSupported
}

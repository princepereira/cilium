// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package xdp

import "github.com/cilium/ebpf/link"

// GetAttachFlags returns the XDP attach flags for the configured TCMode.
func (cfg Config) GetAttachFlags() link.XDPAttachFlags {
	switch cfg.mode {
	case AccelerationModeNative, AccelerationModeBestEffort:
		return link.XDPDriverMode
	case AccelerationModeGeneric:
		return link.XDPGenericMode
	}

	return 0
}

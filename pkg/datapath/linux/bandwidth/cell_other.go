// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bandwidth

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth/types"
)

var defaultConfig = types.Config{
	EnableBandwidthManager: false,
	EnableBBR:              false,
	EnableBBRHostnsOnly:    false,
}

// Cell is a no-op on non-Linux platforms. The real bandwidth manager programs
// tc/EDT qdiscs via netlink, which is Linux-only. It still provides the config
// and a disabled Manager so the rest of the object graph can be satisfied.
var Cell = cell.Module(
	"bandwidth-manager",
	"Linux Bandwidth Manager for EDT-based pacing no-op on non-Linux",

	cell.Config(defaultConfig),
	cell.Provide(newNoopManager),
)

func newNoopManager() Manager {
	return &noopManager{}
}

// noopManager is a disabled implementation of Manager for non-Linux platforms.
type noopManager struct{}

var _ Manager = (*noopManager)(nil)

func (*noopManager) BBREnabled() bool { return false }

func (*noopManager) Enabled() bool { return false }

func (*noopManager) UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32) {}

func (*noopManager) DeleteBandwidthLimit(endpointID uint16) {}

func (*noopManager) UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64) {}

func (*noopManager) DeleteIngressBandwidthLimit(endpointID uint16) {}

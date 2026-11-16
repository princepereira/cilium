// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package netdev

import (
	"github.com/cilium/hive/cell"
)

// NetDevMapSyncCell is a no-op on non-Linux platforms. Synchronizing network
// devices into the cilium_devices BPF map relies on Linux-only datapath state.
var NetDevMapSyncCell = cell.Module(
	"netdev-map-sync",
	"Synchronizes network devices state into the cilium_devices BPF map",
)

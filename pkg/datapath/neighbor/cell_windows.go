// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package neighbor

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/metrics"
)

// Cell is the non-Linux variant of the neighbor subsystem. It provides the
// platform-neutral tables and configuration but omits the netlink-based
// desired-neighbor calculator and reconciler, which have no equivalent on
// non-Linux platforms.
var Cell = cell.Module(
	"neighbor",
	"Neighbor subsystem",

	ForwardableIPCell,

	// Config for the neighbor subsystem, shared by multiple components.
	cell.Config(neighborConfig{EnableL2NeighDiscovery: false}),
	cell.ProvidePrivate(newCommonConfig),

	// Desired neighbor table is an internal table, generated from the forwardable IPs,
	// devices, and routes.
	cell.ProvidePrivate(newDesiredNeighborTable),
	cell.Provide(statedb.RWTable[*DesiredNeighbor].ToTable),

	// Metrics about the neighbor subsystem.
	metrics.Metric(NewNeighborMetrics),
)

// ForwardableIPCell is a separate cell so it can be included independently in
// tests to assert against the contents of the forwardable IP table without
// having to include the entire neighbor subsystem.
var ForwardableIPCell = cell.Group(
	cell.Provide(newForwardableIPTable),
)

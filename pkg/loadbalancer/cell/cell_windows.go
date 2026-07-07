// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cell

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/healthserver"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
)

// Load-balancing control-plane meta cell (Windows).
//
// This mirrors the Linux [Cell] (cell_linux.go) but omits redirectpolicy.Cell.
// CiliumLocalRedirectPolicy support depends on the endpoint manager and the
// skip-LB BPF map, neither of which is available on the Windows/CNC datapath in
// Phase 1 of the port. Everything else -- config, the writer API, reflectors,
// the CNC-backed LBMaps, the reconciler and the health server -- is
// platform-neutral and wired here unchanged.
var Cell = cell.Group(
	// Provides [loadbalancer.Config] and [loadbalancer.ExternalConfig].
	loadbalancer.ConfigCell,

	// Load-balancing tables and the [writer.Writer] API
	writer.Cell,

	// Reflectors from external state to load-balancing tables
	reflectors.Cell,

	// LBMap wrapper around the CNC datapath maps
	maps.Cell,

	// Reconciliation from tables to the datapath.
	reconciler.Cell,

	// Support for HealthCheckNodePort
	healthserver.Cell,

	// /service REST API
	cell.Provide(newServiceRestApiHandler),

	// Provide a function to wait until load-balancing control-plane has received
	// and reconciled the initial state.
	cell.Provide(newInitWaitFunc),
)

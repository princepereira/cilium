// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package reconciler

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/option"
)

type RouteReconcilerMetrics *reconciler.ExpVarMetrics

// registerReconciler is a no-op on non-Linux platforms. Route reconciliation
// relies on netlink, which is only available on Linux.
func registerReconciler(
	params reconciler.Params,
	lc cell.Lifecycle,
	tbl statedb.RWTable[*DesiredRoute],
	devices statedb.Table[*tables.Device],
	log *slog.Logger,
	config *option.DaemonConfig,
) (reconciler.Reconciler[*DesiredRoute], RouteReconcilerMetrics, error) {
	return nil, nil, nil
}

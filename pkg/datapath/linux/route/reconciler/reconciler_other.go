// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package reconciler

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/option"
)

type RouteReconcilerMetrics *reconciler.ExpVarMetrics

type noopReconciler struct{}

func (noopReconciler) Prune() {}

func (noopReconciler) WaitUntilReconciled(ctx context.Context, untilRevision statedb.Revision) (statedb.Revision, statedb.Revision, error) {
	return untilRevision, 0, ctx.Err()
}

func registerReconciler(
	params reconciler.Params,
	lc cell.Lifecycle,
	tbl statedb.RWTable[*DesiredRoute],
	devices statedb.Table[*tables.Device],
	log *slog.Logger,
	config *option.DaemonConfig,
) (reconciler.Reconciler[*DesiredRoute], RouteReconcilerMetrics, error) {
	metrics := reconciler.NewUnpublishedExpVarMetrics()
	return noopReconciler{}, metrics, nil
}

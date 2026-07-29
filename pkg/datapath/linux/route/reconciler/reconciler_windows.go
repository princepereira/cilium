// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package reconciler

import (
	"context"
	"iter"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type RouteReconcilerMetrics *reconciler.ExpVarMetrics

// registerReconciler wires up the desired-route reconciler. On non-Linux
// platforms the kernel routing table is not manipulated via netlink, so the
// reconciler operations are no-ops: desired routes are still tracked in
// StateDB but never programmed into the kernel.
func registerReconciler(
	params reconciler.Params,
	lc cell.Lifecycle,
	tbl statedb.RWTable[*DesiredRoute],
	devices statedb.Table[*tables.Device],
	log *slog.Logger,
	config *option.DaemonConfig,
) (reconciler.Reconciler[*DesiredRoute], RouteReconcilerMetrics, error) {
	metrics := reconciler.NewUnpublishedExpVarMetrics()
	ops := &noopOps{}
	rec, err := reconciler.Register(
		params,
		tbl,
		(*DesiredRoute).Clone,
		(*DesiredRoute).SetStatus,
		(*DesiredRoute).GetStatus,
		ops,
		ops,
		reconciler.WithPruning(30*time.Minute),
		reconciler.WithMetrics(metrics),
	)
	return rec, metrics, err
}

// noopOps implements reconciler.Operations and reconciler.BatchOperations
// without touching the kernel.
type noopOps struct{}

func (*noopOps) Update(context.Context, statedb.ReadTxn, statedb.Revision, *DesiredRoute) error {
	return nil
}

func (*noopOps) Delete(context.Context, statedb.ReadTxn, statedb.Revision, *DesiredRoute) error {
	return nil
}

func (*noopOps) Prune(context.Context, statedb.ReadTxn, iter.Seq2[*DesiredRoute, statedb.Revision]) error {
	return nil
}

func (*noopOps) UpdateBatch(_ context.Context, _ statedb.ReadTxn, batch []reconciler.BatchEntry[*DesiredRoute]) {
}

func (*noopOps) DeleteBatch(_ context.Context, _ statedb.ReadTxn, batch []reconciler.BatchEntry[*DesiredRoute]) {
}

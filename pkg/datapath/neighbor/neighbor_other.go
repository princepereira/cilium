// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package neighbor

import (
	"context"
	"iter"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

type netlinkFuncsGetter struct{}

func newNetlinkFuncsGetter(lifecycle cell.Lifecycle) *netlinkFuncsGetter {
	return &netlinkFuncsGetter{}
}

type desiredNeighborCalculatorParams struct {
	cell.In

	DB                   *statedb.DB
	DesiredNeighborTable statedb.RWTable[*DesiredNeighbor]
	ForwardableIPTable   statedb.Table[*ForwardableIP]
	DeviceTable          statedb.Table[*tables.Device]
	RouteTable           statedb.Table[*tables.Route]
	FuncsGetter          *netlinkFuncsGetter
	Metrics              *neighborMetrics
	Config               *CommonConfig

	JobGroup job.Group
}

type desiredNeighborCalculator struct{}

func newDesiredNeighborCalculator(p desiredNeighborCalculatorParams) (*desiredNeighborCalculator, error) {
	return nil, nil
}

func newOps(
	neighbors statedb.Table[*tables.Neighbor],
	desiredNeighbors statedb.Table[*DesiredNeighbor],
	funcsGetter *netlinkFuncsGetter,
	config *CommonConfig,
	metrics *neighborMetrics,
) reconciler.Operations[*DesiredNeighbor] {
	return &ops{}
}

var _ reconciler.Operations[*DesiredNeighbor] = (*ops)(nil)

type ops struct{}

func (ops *ops) Update(ctx context.Context, rx statedb.ReadTxn, rev statedb.Revision, neighbor *DesiredNeighbor) error {
	return nil
}

func (ops *ops) Delete(ctx context.Context, rx statedb.ReadTxn, rev statedb.Revision, neighbor *DesiredNeighbor) error {
	return nil
}

func (ops *ops) Prune(ctx context.Context, rx statedb.ReadTxn, desired iter.Seq2[*DesiredNeighbor, statedb.Revision]) error {
	return nil
}

func newNeighborReconciler(
	params reconciler.Params,
	ops reconciler.Operations[*DesiredNeighbor],
	tbl statedb.RWTable[*DesiredNeighbor],
	config *CommonConfig,
) (reconciler.Reconciler[*DesiredNeighbor], error) {
	return nil, nil
}

func newNeighborRefresher(
	db *statedb.DB,
	neighbors statedb.Table[*tables.Neighbor],
	desiredNeighbors statedb.RWTable[*DesiredNeighbor],
	jobGroup job.Group,
	metrics *neighborMetrics,
	config *CommonConfig,
) {
}

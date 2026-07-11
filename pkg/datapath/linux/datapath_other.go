// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linux

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	dpTunnel "github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/node/manager"
)

// DevicesControllerCell provides the device, route and neighbor tables so that
// downstream cells requiring them can be satisfied on non-Linux platforms.
var DevicesControllerCell = cell.Module(
	"devices-controller",
	"Synchronizes the device route and neighbor tables with the kernel",
	cell.Provide(
		tables.NewDeviceTable,
		statedb.RWTable[*tables.Device].ToTable,
		tables.NewRouteTable,
		statedb.RWTable[*tables.Route].ToTable,
		tables.NewNeighborTable,
		statedb.RWTable[*tables.Neighbor].ToTable,
	),
)

// BackendNeighborSyncCell synchronizes backends to the neighbors table. On
// non-Linux platforms this is a no-op module.
var BackendNeighborSyncCell = cell.Module(
	"backend-neighbor-sync",
	"Synchronizes backends to Linux neighbors table",
)

// NewNodeHandler returns a fake node handler that satisfies both the
// node.Handler and node.IDHandler interfaces on non-Linux platforms.
func NewNodeHandler(
	lifecycle cell.Lifecycle,
	log *slog.Logger,
	tunnelConfig dpTunnel.Config,
	nodeMap nodemap.MapV2,
	nodeManager manager.NodeManager,
	nodeConfigNotifier *manager.NodeConfigNotifier,
	kprCfg kpr.KPRConfig,
	ipsecAgent ipsecTypes.Agent,
	localNodeStore *node.LocalNodeStore,
) (node.Handler, node.IDHandler) {
	h := fakenode.NewHandler()
	nodeManager.Subscribe(h)
	return h, h
}

// CheckRequirements is a no-op on non-Linux platforms.
func CheckRequirements(log *slog.Logger) error { return nil }

// NodeEnsureLocalRoutingRule is a no-op on non-Linux platforms.
func NodeEnsureLocalRoutingRule() error { return nil }

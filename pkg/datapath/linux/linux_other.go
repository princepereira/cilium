// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linux

import (
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/api/v1/models"
	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	dpTunnel "github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/maps/nodemap"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

// DevicesControllerCell is a no-op on non-Linux platforms. The real
// implementation relies on netlink route/address/link subscriptions that are
// only available on Linux. It still owns and provides the device, route and
// neighbor tables so that the rest of the object graph can be satisfied; on
// non-Linux platforms these tables simply remain empty.
var DevicesControllerCell = cell.Module(
	"devices-controller",
	"Manages the device and route tables no-op on non-Linux",

	// The tables register themselves with the database on construction and
	// stay empty since there is no netlink subscriber to populate them.
	cell.ProvidePrivate(
		tables.NewDeviceTable,
		tables.NewRouteTable,
		tables.NewNeighborTable,
	),
	cell.Provide(
		statedb.RWTable[*tables.Device].ToTable,
		statedb.RWTable[*tables.Route].ToTable,
		statedb.RWTable[*tables.Neighbor].ToTable,
	),
)

// CheckRequirements is a no-op on non-Linux platforms.
func CheckRequirements(log *slog.Logger) error {
	return nil
}

// NodeEnsureLocalRoutingRule is a no-op on non-Linux platforms.
func NodeEnsureLocalRoutingRule() error {
	return nil
}

// nodeHandlerStub is a no-op implementation of node.Handler and node.IDHandler
// used to satisfy the datapath wiring on non-Linux platforms.
type nodeHandlerStub struct{}

var (
	_ node.Handler   = (*nodeHandlerStub)(nil)
	_ node.IDHandler = (*nodeHandlerStub)(nil)
)

func (nodeHandlerStub) Name() string                                     { return "linux-node-handler" }
func (nodeHandlerStub) NodeAdd(newNode nodeTypes.Node) error             { return nil }
func (nodeHandlerStub) NodeUpdate(oldNode, newNode nodeTypes.Node) error { return nil }
func (nodeHandlerStub) NodeDelete(node nodeTypes.Node) error             { return nil }
func (nodeHandlerStub) AllNodeValidateImplementation()                   {}
func (nodeHandlerStub) NodeValidateImplementation(node nodeTypes.Node) error {
	return nil
}

func (nodeHandlerStub) GetNodeIP(uint16) string                { return "" }
func (nodeHandlerStub) GetNodeID(nodeIP net.IP) (uint16, bool) { return 0, false }
func (nodeHandlerStub) DumpNodeIDs() []*models.NodeID          { return nil }
func (nodeHandlerStub) RestoreNodeIDs()                        {}

// NewNodeHandler returns a no-op node handler on non-Linux platforms.
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
	h := &nodeHandlerStub{}
	return h, h
}

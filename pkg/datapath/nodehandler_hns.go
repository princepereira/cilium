// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package datapath

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/node"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/windows/hcs"
	"github.com/cilium/cilium/pkg/windows/hns"
)

// ciliumHNSNetworkName is the HNS network on which remote-node overlay routes
// are programmed. It matches the network created for the Cilium Windows
// datapath.
const ciliumHNSNetworkName = "cilium"

// hnsNodeHandler is the Windows datapath node handler. It reuses the fake
// handler for in-memory node/ID bookkeeping (which the node manager relies on)
// and additionally programs remote-node pod CIDRs as HNS RemoteSubnetRoute
// policies via the native HNS/HCN datapath.
//
// Route programming is best-effort: when HNS is unavailable (Available() ==
// false, e.g. a developer machine) the operations are no-ops and node events
// are still tracked in memory, so the agent continues to run.
type hnsNodeHandler struct {
	*fakenode.Handler

	logger *slog.Logger
	hns    hns.Manager
}

// newHNSNodeHandler constructs the Windows node handler and subscribes it to
// the node manager so it receives node add/update/delete events.
func newHNSNodeHandler(logger *slog.Logger, nodeManager manager.NodeManager) (node.Handler, node.IDHandler) {
	h := &hnsNodeHandler{
		Handler: fakenode.NewHandler(),
		logger:  logger,
		hns:     hns.New(logger),
	}
	nodeManager.Subscribe(h)
	return h, h
}

func (h *hnsNodeHandler) Name() string { return "hns-node-handler" }

func (h *hnsNodeHandler) NodeAdd(newNode nodeTypes.Node) error {
	if err := h.Handler.NodeAdd(newNode); err != nil {
		return err
	}
	h.programNodeRoutes(newNode, true)
	return nil
}

func (h *hnsNodeHandler) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	if err := h.Handler.NodeUpdate(oldNode, newNode); err != nil {
		return err
	}
	// Withdraw stale routes, then (re)program the current ones. Both are
	// best-effort and no-op when HNS is unavailable.
	h.programNodeRoutes(oldNode, false)
	h.programNodeRoutes(newNode, true)
	return nil
}

func (h *hnsNodeHandler) NodeDelete(oldNode nodeTypes.Node) error {
	h.programNodeRoutes(oldNode, false)
	return h.Handler.NodeDelete(oldNode)
}

// programNodeRoutes adds (add==true) or removes the RemoteSubnetRoute policies
// for a remote node's pod CIDRs. The local node is skipped: its pod CIDR is
// served locally rather than via an overlay route.
func (h *hnsNodeHandler) programNodeRoutes(n nodeTypes.Node, add bool) {
	if h.hns == nil || !h.hns.Available() {
		return
	}
	if n.IsLocal() {
		return
	}

	provider, ok := netip.AddrFromSlice(n.GetNodeInternalIPv4())
	if !ok {
		return
	}
	provider = provider.Unmap()

	for _, c := range n.GetIPv4AllocCIDRs() {
		if c == nil {
			continue
		}
		prefix, err := netip.ParsePrefix(c.String())
		if err != nil {
			continue
		}
		route := hns.RemoteNodeRoute{
			DestinationPrefix: prefix.Masked(),
			ProviderAddress:   provider,
		}
		if !route.Valid() {
			continue
		}

		var opErr error
		if add {
			opErr = h.hns.AddRemoteNodeRoute(ciliumHNSNetworkName, route)
		} else {
			opErr = h.hns.RemoveRemoteNodeRoute(ciliumHNSNetworkName, route)
		}
		if opErr != nil {
			h.logger.Warn("failed to program HNS remote node route",
				"node", n.Name,
				"prefix", route.DestinationPrefix,
				"provider", route.ProviderAddress,
				"add", add,
				"error", opErr,
			)
		}
	}
}

// newHCSManager provides the native Windows container query manager to the
// hive. It is disabled (no-op) on non-Windows platforms and on Windows hosts
// without the Host Compute System.
func newHCSManager(logger *slog.Logger) hcs.Manager {
	return hcs.New(logger)
}

// logHCSStatus forces construction of the HCS manager and records whether the
// native container-correlation datapath is active.
func logHCSStatus(logger *slog.Logger, mgr hcs.Manager) {
	if mgr.Available() {
		logger.Info("native Windows container correlation (HCS) is active")
	}
}

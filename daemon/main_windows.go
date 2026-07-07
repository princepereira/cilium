// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package main

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathtables "github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	k8stables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// Minimal Windows cilium-agent (WORK IN PROGRESS).
//
// This is the Windows entrypoint for the incremental port. It boots the Hive
// framework (which brings StateDB + jobs from pkg/hive) and wires the
// load-balancer control-plane on the CNC datapath. The full Linux agent lives
// in daemon/cmd (Linux-only).
//
// Phase 1 wires the complete load-balancer chain:
//
//	reflectors -> writer -> StateDB tables -> reconciler -> CNCLBMaps (CNC datapath)
//
// via loadbalancer/cell.Cell (the Windows variant, which omits redirectpolicy;
// see pkg/loadbalancer/cell/cell_windows.go). The infrastructure below provides
// the dependencies that on Linux come from the full daemon: the k8s client, the
// local node store, the node-address and pod tables, Maglev, and the various
// configuration objects. Several of these are minimal placeholders for Phase 1
// (e.g. the node-address table is created empty rather than being populated by
// the netlink DevicesController); they are sufficient to construct and start
// the load-balancer control-plane.

// windowsInfra provides the minimal infrastructure dependencies required by the
// load-balancer control-plane on Windows.
var windowsInfra = cell.Module(
	"windows-infra",
	"Minimal Windows agent infrastructure",

	// Kubernetes client. With no kubeconfig configured the clientset is
	// disabled and the reflectors degrade to a no-op.
	k8sclient.Cell,

	// Local node store + Table[*node.LocalNode]. The test cell provides a
	// no-op LocalNodeSynchronizer; a CNC-backed synchronizer will replace it.
	node.LocalNodeStoreTestCell,

	// Maglev consistent-hash table computation (portable). Provides
	// *maglev.Maglev and maglev.Config.
	maglev.Cell,

	// Node-IPAM and LB-IPAM configuration (interfaces provided by their own
	// cells; used by loadbalancer.NewExternalConfig).
	nodeipamconfig.Cell,
	lbipamconfig.Cell,

	cell.Provide(
		// Node-address table. On Linux this is populated by the netlink
		// DevicesController; on Windows we expose it empty for Phase 1 and
		// will source addresses from the LocalNodeStore later.
		datapathtables.NewNodeAddressTable,
		statedb.RWTable[datapathtables.NodeAddress].ToTable,

		// Pod table (empty; no reflector wired for Phase 1).
		k8stables.NewPodTable,
		statedb.RWTable[k8stables.LocalPod].ToTable,

		// Source registry used by the writer/reflectors.
		source.NewSources,

		// Configuration objects that on Linux are provided by dedicated
		// config cells. Minimal values are sufficient to construct the
		// load-balancer control-plane on Windows.
		func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableIPv4: true,
				EnableIPv6: false,
			}
		},
		func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
		func() kpr.KPRConfig { return kpr.KPRConfig{} },
		func() k8s.Config { return k8s.Config{} },
		func() k8s.ServiceWatchConfig { return k8s.ServiceWatchConfig{} },
	),
)

var agentCell = cell.Module(
	"agent",
	"Cilium Agent - Windows minimal",

	// Minimal infrastructure (k8s client, node store, tables, config).
	windowsInfra,

	// Load-balancer control-plane on the CNC datapath: config, StateDB
	// tables + Writer, reflectors, CNC-backed LBMaps, reconciler and the
	// health server.
	lbcell.Cell,

	// Report readiness of the load-balancer control-plane on startup.
	cell.Invoke(func(lc cell.Lifecycle, log *slog.Logger, _ *writer.Writer) {
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				log.Info("Minimal Windows cilium-agent started: load-balancer control-plane wired to the CNC datapath",
					logfields.LogSubsys, "windows-agent",
				)
				return nil
			},
		})
	}),
)

func main() {
	h := hive.New(agentCell)
	if err := h.Run(logging.DefaultSlogLogger); err != nil {
		logging.Fatal(logging.DefaultSlogLogger, "unable to run minimal Windows cilium-agent: "+err.Error())
	}
}

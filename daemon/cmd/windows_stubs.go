// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8stables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/reflectors"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/statedb"
)

var (
	Agent = cell.Module("agent", "Cilium Agent Windows",
		// CNCShim client — connects to the Windows datapath shim
		winDatapath.Cell,

		// Kubernetes client — connects to the K8s API server
		client.Cell,

		// Local node store — required by writer for zone-aware LB
		cell.Provide(node.NewNopLocalNodeSynchronizer),
		cell.Config(cmtypes.DefaultClusterInfo),
		node.LocalNodeStoreCell,

		// Provide DaemonConfig (required by loadbalancer.ConfigCell)
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				EnableIPv4: true,
				EnableIPv6: true,
			}
		}),

		// Provide source priorities (required by writer)
		cell.Provide(source.NewSources),

		// Provide NodeAddress table (required by writer for NodePort addresses)
		cell.Provide(
			tables.NewNodeAddressTable,
			statedb.RWTable[tables.NodeAddress].ToTable,
		),

		// Provide LocalPod table (required by K8s reflector)
		cell.Provide(k8stables.NewPodTableAndReflector),

		// K8s resource configs (required by K8s reflector)
		cell.Config(k8s.DefaultConfig),
		cell.Provide(k8s.DefaultServiceWatchConfig),

		// Additional configs required by K8s reflector
		kpr.Cell,
		nodeipamconfig.Cell,
		lbipamconfig.Cell,

		// Maglev config (required by LBMaps params)
		maglev.Cell,

		// Load-balancing control-plane: tables, writer, reflectors, maps, reconciler
		loadbalancer.ConfigCell,
		writer.Cell,
		reflectors.Cell,
		maps.Cell,
		reconciler.Cell,

		// Wiring: connect CNCClient to CNCLBMaps at startup
		cell.Invoke(wireCNCClientToLBMaps),
	)

	Infrastructure      = cell.Module("infra", "Infrastructure")
	ControlPlane        = cell.Module("controlplane", "Control Plane")
	hostIPSyncCell      = cell.Module("hostip-sync", "Syncs local host entries")
	endpointRestoreCell = cell.Module("endpoint-restore", "Endpoint restoration")
)

// wireCNCClientToLBMaps connects the CNCClient API to the CNCLBMaps implementation.
func wireCNCClientToLBMaps(lc cell.Lifecycle, client *winDatapath.CNCClient, lbMaps maps.LBMaps) {
	type apiSetter interface {
		SetAPI(api interface{})
	}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			go func() {
				select {
				case <-client.Ready():
					api := client.API()
					if api != nil {
						if setter, ok := lbMaps.(apiSetter); ok {
							setter.SetAPI(api)
						}
						slog.Info("CNC API connected to LBMaps")
					}
				}
			}()
			return nil
		},
	})
}

type endpointRestorer struct{}

// NewAgentCmd creates the cilium-agent cobra command for Windows.
func NewAgentCmd(newHive func() *hive.Hive) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cilium-agent",
		Short: "Cilium Agent for Windows nodes (powered by cncshim)",
		RunE: func(cmd *cobra.Command, args []string) error {
			h := newHive()
			if err := h.Start(slog.Default(), cmd.Context()); err != nil {
				return fmt.Errorf("failed to start hive: %w", err)
			}

			slog.Info("Cilium agent started on Windows")

			// Wait for shutdown signal
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			<-ctx.Done()

			slog.Info("Shutting down cilium agent")
			if err := h.Stop(slog.Default(), context.Background()); err != nil {
				slog.Error("Error during shutdown", "error", err)
				return err
			}
			return nil
		},
	}
	return cmd
}

// Execute runs the provided cobra command.
func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func (*endpointRestorer) WaitForEndpointRestoreWithoutRegeneration(context.Context) error { return nil }
func (*endpointRestorer) WaitForEndpointRestore(context.Context) error                    { return nil }
func (*endpointRestorer) WaitForInitialPolicy(context.Context) error                      { return nil }

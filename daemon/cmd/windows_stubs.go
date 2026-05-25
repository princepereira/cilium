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

	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
)

var (
	Agent = cell.Module("agent", "Cilium Agent Windows",
		// CNCShim client — connects to the Windows datapath shim
		winDatapath.Cell,

		// K8s watcher — watches Services/EndpointSlices and programs cncshim
		winDatapath.K8sWatcherCell,
	)

	Infrastructure      = cell.Module("infra", "Infrastructure")
	ControlPlane        = cell.Module("controlplane", "Control Plane")
	hostIPSyncCell      = cell.Module("hostip-sync", "Syncs local host entries")
	endpointRestoreCell = cell.Module("endpoint-restore", "Endpoint restoration")
)

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

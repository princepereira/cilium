// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/spf13/cobra"
)

var (
	Agent              = cell.Module("agent", "Cilium Agent")
	Infrastructure     = cell.Module("infra", "Infrastructure")
	ControlPlane       = cell.Module("controlplane", "Control Plane")
	hostIPSyncCell     = cell.Module("hostip-sync", "Syncs local host entries")
	endpointRestoreCell = cell.Module("endpoint-restore", "Endpoint restoration")
)

type endpointRestorer struct{}

func NewAgentCmd(func() *hive.Hive) *cobra.Command { return &cobra.Command{Use: "cilium-agent"} }

// Execute runs the provided cobra command.
func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func (*endpointRestorer) WaitForEndpointRestoreWithoutRegeneration(context.Context) error { return nil }
func (*endpointRestorer) WaitForEndpointRestore(context.Context) error                     { return nil }
func (*endpointRestorer) WaitForInitialPolicy(context.Context) error                      { return nil }

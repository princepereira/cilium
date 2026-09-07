// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package genericveth

import (
	"context"
	"errors"
	"fmt"

	cniTypes "github.com/containernetworking/cni/pkg/types"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type GenericVethChainer struct{}

func (f *GenericVethChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext, delClient *lib.DeletionFallbackClient) (err error) {
	if err := delClient.EndpointDelete(pluginCtx.Args.ContainerID, pluginCtx.Args.IfName); err != nil {
		if errors.Is(err, lib.ErrClientFailure) {
			pluginCtx.Logger.Error("Failed to delete endpoint", logfields.Error, err)
			return err
		}

		pluginCtx.Logger.Warn(
			"Errors encountered while deleting endpoint",
			logfields.Error, err,
		)
	}
	return nil
}

func (f *GenericVethChainer) Check(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	// Just confirm that the endpoint is healthy
	eID := endpointid.NewCNIAttachmentID(pluginCtx.Args.ContainerID, pluginCtx.Args.IfName)
	pluginCtx.Logger.Warn(
		"Asking agent for healthz for endpoint",
		logfields.EndpointID, eID,
	)
	epHealth, err := cli.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	pluginCtx.Logger.Debug(
		"Container has a healthy agent endpoint",
		logfields.ContainerID, pluginCtx.Args.ContainerID,
		logfields.Interface, pluginCtx.Args.IfName,
	)
	return nil
}

func (f *GenericVethChainer) Status(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	if _, err := cli.Daemon.GetHealthzContext(ctx, daemon.NewGetHealthzParams()); err != nil {
		return cniTypes.NewError(types.CniErrPluginNotAvailable, "DaemonHealthzFailed",
			fmt.Sprintf("Cilium agent healthz check failed: %s", client.Hint(err)))
	}
	return nil
}

func init() {
	chainingapi.Register("generic-veth", &GenericVethChainer{})
}

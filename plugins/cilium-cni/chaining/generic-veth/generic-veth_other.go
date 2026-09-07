// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package genericveth

import (
	"context"
	"fmt"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"

	"github.com/cilium/cilium/pkg/client"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
)

// Add is not supported on non-Linux platforms where veth/netlink-based CNI
// chaining is unavailable.
func (f *GenericVethChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	return nil, fmt.Errorf("generic-veth chaining is not supported on this platform")
}

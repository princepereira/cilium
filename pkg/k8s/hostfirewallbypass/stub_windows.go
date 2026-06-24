// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package hostfirewallbypass

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"k8s-host-firewall-bypass",
	"Windows stub",
	cell.Config(config{EnableK8sHostFirewallBypass: true}),
	cell.Provide(NewK8sHostFirewallBypass),
)

type Params struct {
	cell.In

	DaemonConfig *option.DaemonConfig `optional:"true"`
	LocalConfig  config
}

type config struct {
	EnableK8sHostFirewallBypass bool
}

func (p config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-k8s-host-firewall-bypass", p.EnableK8sHostFirewallBypass, "Enable bypassing host firewall for Kubernetes API server access.")
	flags.MarkHidden("enable-k8s-host-firewall-bypass")
}

func NewK8sHostFirewallBypass(Params) client.ConfigureK8sClientsetDialer {
	return nil
}

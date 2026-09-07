// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hostfirewallbypass

import (
	"net"

	"github.com/cilium/cilium/pkg/k8s/client"
)

type k8sHostFirewallBypass struct{}

func NewK8sHostFirewallBypass(params Params) client.ConfigureK8sClientsetDialer {
	if params.DaemonConfig != nil && !params.DaemonConfig.EnableHostFirewall {
		return nil
	}
	if params.LocalConfig.EnableK8sHostFirewallBypass {
		return &k8sHostFirewallBypass{}
	} else {
		return nil
	}
}

// Sets SO_MARK so that connections to kube-apiserver bypass host firewall and DNS proxy
func (*k8sHostFirewallBypass) ConfigureK8sClientsetDialer(dialer *net.Dialer) {
	dialer.Control = setProxyEgressMark
	dialer.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: (&net.Dialer{
			Control: setProxyEgressMark,
		}).DialContext,
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package hostfirewallbypass

import "github.com/cilium/cilium/pkg/k8s/client"

func NewK8sHostFirewallBypass(params Params) client.ConfigureK8sClientsetDialer {
	return nil
}

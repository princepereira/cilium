// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package proxy

import linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"

// nodeEnsureLocalRoutingRule installs the local routing rule required to route
// proxy traffic. This is a Linux datapath operation.
func nodeEnsureLocalRoutingRule() error {
	return linuxdatapath.NodeEnsureLocalRoutingRule()
}

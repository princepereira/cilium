// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipam

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// configureENIDevices is a no-op on non-Linux platforms, where ENI network
// devices cannot be configured via netlink.
func configureENIDevices(logger *slog.Logger, oldNode, newNode *ciliumv2.CiliumNode, mtuConfig MtuConfiguration, sysctl sysctl.Sysctl) {
}

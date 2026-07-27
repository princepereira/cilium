// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package endpoint

import (
	"net"
)

// hostEndpointIfaceAttrs returns the hardware address and interface index of
// the host datapath device. On non-Linux platforms there is no cilium_host
// netlink device, so a dummy (empty MAC, ifindex 0) is returned. The host
// endpoint object is still created so the control plane can operate; native
// datapath wiring (e.g. via HNS on Windows) is layered in separately.
func hostEndpointIfaceAttrs() (net.HardwareAddr, int, error) {
	return net.HardwareAddr{}, 0, nil
}

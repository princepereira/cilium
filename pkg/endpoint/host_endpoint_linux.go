// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package endpoint

import (
	"net"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
)

// hostEndpointIfaceAttrs returns the hardware address and interface index of
// the host datapath device. On Linux these are read from the cilium_host
// netlink device.
func hostEndpointIfaceAttrs() (net.HardwareAddr, int, error) {
	iface, err := safenetlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return nil, 0, err
	}
	return iface.Attrs().HardwareAddr, iface.Attrs().Index, nil
}

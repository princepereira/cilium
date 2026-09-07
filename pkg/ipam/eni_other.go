// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipam

import (
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

// waitForNetlinkDevices is a no-op on non-Linux platforms where netlink-based
// ENI device discovery is not available.
func waitForNetlinkDevices(logger *slog.Logger, configByMac configMap) (linkByMac linkMap, err error) {
	return linkMap{}, nil
}

// configureENINetlinkDevice is a no-op on non-Linux platforms where netlink is
// not available.
func configureENINetlinkDevice(link netlink.Link, cfg eniDeviceConfig, sysctl sysctl.Sysctl) error {
	return nil
}

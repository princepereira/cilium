// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package netdevice

import (
	"fmt"
	"net/netip"
	"runtime"
)

// These helpers rely on netlink to enumerate interface addresses, which is not
// available outside of Linux. They return errors on other platforms.

func GetIfaceFirstIPv4Address(ifaceName string) (netip.Addr, error) {
	return netip.Addr{}, fmt.Errorf("netdevice address lookup is not supported on %s", runtime.GOOS)
}

func TestForIfaceWithIPv4Address(ip netip.Addr) error {
	return fmt.Errorf("netdevice address lookup is not supported on %s", runtime.GOOS)
}

func GetIfaceWithIPv4Address(ip netip.Addr) (string, error) {
	return "", fmt.Errorf("netdevice address lookup is not supported on %s", runtime.GOOS)
}

func GetIfaceFirstIPv6Address(ifaceName string) (netip.Addr, error) {
	return netip.Addr{}, fmt.Errorf("netdevice address lookup is not supported on %s", runtime.GOOS)
}

func GetIfaceWithIPv6Address(ip netip.Addr) (string, error) {
	return "", fmt.Errorf("netdevice address lookup is not supported on %s", runtime.GOOS)
}

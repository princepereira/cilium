// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netdevice

import (
	"fmt"
	"net/netip"
)

func GetIfaceFirstIPv4Address(string) (netip.Addr, error) {
	return netip.Addr{}, fmt.Errorf("not supported on Windows")
}

func TestForIfaceWithIPv4Address(ip netip.Addr) error {
	_, err := GetIfaceWithIPv4Address(ip)
	return err
}

func GetIfaceWithIPv4Address(netip.Addr) (string, error) {
	return "", fmt.Errorf("not supported on Windows")
}

func GetIfaceFirstIPv6Address(string) (netip.Addr, error) {
	return netip.Addr{}, fmt.Errorf("not supported on Windows")
}

func GetIfaceWithIPv6Address(netip.Addr) (string, error) {
	return "", fmt.Errorf("not supported on Windows")
}

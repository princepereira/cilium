// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package netdevice

import (
	"fmt"
	"net/netip"
)

var errUnsupportedOp = fmt.Errorf("netdevice operations are not supported on this platform")

func GetIfaceFirstIPv4Address(ifaceName string) (netip.Addr, error) {
	return netip.Addr{}, errUnsupportedOp
}

func TestForIfaceWithIPv4Address(ip netip.Addr) error {
	return errUnsupportedOp
}

func GetIfaceWithIPv4Address(ip netip.Addr) (string, error) {
	return "", errUnsupportedOp
}

func GetIfaceFirstIPv6Address(ifaceName string) (netip.Addr, error) {
	return netip.Addr{}, errUnsupportedOp
}

func GetIfaceWithIPv6Address(ip netip.Addr) (string, error) {
	return "", errUnsupportedOp
}

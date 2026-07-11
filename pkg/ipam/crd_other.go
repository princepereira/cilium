// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipam

import "net"

// removeUnreachableRoute is a no-op on non-Linux platforms, where unreachable
// routes are not programmed via netlink.
func removeUnreachableRoute(ip net.IP) error {
	return nil
}

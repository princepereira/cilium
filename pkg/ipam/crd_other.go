// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipam

import "net"

// delUnreachableRoute is a no-op on non-Linux platforms where netlink route
// management is not available.
func delUnreachableRoute(parsedIP net.IP) error {
	return nil
}

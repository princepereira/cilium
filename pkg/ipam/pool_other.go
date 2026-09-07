// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipam

import "net/netip"

// cleanupUnreachableRoutes is a no-op on non-Linux platforms where netlink
// route management is not available.
func cleanupUnreachableRoutes(prefix netip.Prefix) error {
	return nil
}

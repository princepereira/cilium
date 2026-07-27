// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// This file is not part of upstream vishvananda/netlink. It provides the
// address-family and route-scope constants that upstream only defines in its
// Linux-specific files (netlink_linux.go, route_linux.go). Cilium's
// cross-platform code references these constants at compile time, so they are
// defined here for non-Linux builds using their stable Linux ABI values.

package netlink

const (
	FAMILY_ALL  = 0
	FAMILY_V4   = 2  // unix.AF_INET
	FAMILY_V6   = 10 // unix.AF_INET6
	FAMILY_MPLS = 28 // unix.AF_MPLS
)

const (
	SCOPE_UNIVERSE Scope = 0
	SCOPE_SITE     Scope = 200
	SCOPE_LINK     Scope = 253
	SCOPE_HOST     Scope = 254
	SCOPE_NOWHERE  Scope = 255
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package mtu

// Mirror of the Linux netlink address family and route next-hop flag constants
// used for MTU route reconciliation. The netlink and unix packages do not
// export these on non-Linux platforms.
const (
	nlFamilyAll = 0  // netlink.FAMILY_ALL (AF_UNSPEC)
	nlFamilyV4  = 2  // netlink.FAMILY_V4 (AF_INET)
	nlFamilyV6  = 10 // netlink.FAMILY_V6 (AF_INET6)

	rtnhFlagLinkDown = 16 // unix.RTNH_F_LINKDOWN
	rtnhFlagDead     = 1  // unix.RTNH_F_DEAD
)

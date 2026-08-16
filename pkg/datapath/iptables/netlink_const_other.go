// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package iptables

// Mirror of the Linux netlink address family constants. The netlink package
// does not export these on non-Linux platforms.
const (
	nlFamilyV4 = 2  // netlink.FAMILY_V4 (AF_INET)
	nlFamilyV6 = 10 // netlink.FAMILY_V6 (AF_INET6)
)

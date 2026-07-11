// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipfamily

import "golang.org/x/sys/unix"

const (
	socketOptsFamilyIPv4          = unix.SOL_IP
	socketOptsTransparentIPv4     = unix.IP_TRANSPARENT
	socketOptsRecvOrigDstAddrIPv4 = unix.IP_RECVORIGDSTADDR

	socketOptsFamilyIPv6          = unix.SOL_IPV6
	socketOptsTransparentIPv6     = unix.IPV6_TRANSPARENT
	socketOptsRecvOrigDstAddrIPv6 = unix.IPV6_RECVORIGDSTADDR
)
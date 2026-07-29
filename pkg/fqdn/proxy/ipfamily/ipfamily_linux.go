// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipfamily

import "golang.org/x/sys/unix"

const (
	sockoptIPv4Family          = unix.SOL_IP
	sockoptIPv4Transparent     = unix.IP_TRANSPARENT
	sockoptIPv4RecvOrigDstAddr = unix.IP_RECVORIGDSTADDR

	sockoptIPv6Family          = unix.SOL_IPV6
	sockoptIPv6Transparent     = unix.IPV6_TRANSPARENT
	sockoptIPv6RecvOrigDstAddr = unix.IPV6_RECVORIGDSTADDR
)

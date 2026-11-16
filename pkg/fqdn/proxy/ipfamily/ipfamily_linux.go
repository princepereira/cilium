// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipfamily

import "golang.org/x/sys/unix"

const (
	solIP               = unix.SOL_IP
	ipTransparent       = unix.IP_TRANSPARENT
	ipRecvOrigDstAddr   = unix.IP_RECVORIGDSTADDR
	solIPv6             = unix.SOL_IPV6
	ipv6Transparent     = unix.IPV6_TRANSPARENT
	ipv6RecvOrigDstAddr = unix.IPV6_RECVORIGDSTADDR
)

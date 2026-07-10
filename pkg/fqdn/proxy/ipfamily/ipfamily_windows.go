// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ipfamily

import "golang.org/x/sys/windows"

// Windows has no equivalent of the Linux TPROXY socket options
// IP(V6)_TRANSPARENT and IP(V6)_RECVORIGDSTADDR. Transparent interception and
// original-destination recovery are handled by the Windows Filtering Platform
// (WFP) connect-redirect layers, not by socket options, so those fields are
// left as 0 (unsupported / no-op). Only the setsockopt level is meaningful.
func IPv4() IPFamily {
	return IPFamily{
		Name:       "ipv4",
		UDPAddress: "udp4",
		TCPAddress: "tcp4",
		Localhost:  "127.0.0.1",

		SocketOptsFamily:          windows.IPPROTO_IP,
		SocketOptsTransparent:     0,
		SocketOptsRecvOrigDstAddr: 0,
	}
}

func IPv6() IPFamily {
	return IPFamily{
		Name:       "ipv6",
		UDPAddress: "udp6",
		TCPAddress: "tcp6",
		Localhost:  "::1",

		SocketOptsFamily:          windows.IPPROTO_IPV6,
		SocketOptsTransparent:     0,
		SocketOptsRecvOrigDstAddr: 0,
	}
}

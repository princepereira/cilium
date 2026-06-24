// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ipfamily

import "net"

// IPFamily defines IP family specific properties.
type IPFamily struct {
	Name            string
	Localhost       string
	UDPAddr         *net.UDPAddr
	SocketOptLevel  int
	TransparentOpt  int
	RecvOrigDstAddr int
}

// IPv4 returns the IPv4 IPFamily properties.
func IPv4() IPFamily {
	return IPFamily{
		Name:      "ipv4",
		Localhost: "127.0.0.1",
		UDPAddr:   &net.UDPAddr{IP: net.IPv4zero},
	}
}

// IPv6 returns the IPv6 IPFamily properties.
func IPv6() IPFamily {
	return IPFamily{
		Name:      "ipv6",
		Localhost: "::1",
		UDPAddr:   &net.UDPAddr{IP: net.IPv6zero},
	}
}

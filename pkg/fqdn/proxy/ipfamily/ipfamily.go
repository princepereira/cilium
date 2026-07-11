// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipfamily

type IPFamily struct {
	Name       string
	UDPAddress string
	TCPAddress string
	Localhost  string

	SocketOptsFamily          int
	SocketOptsTransparent     int
	SocketOptsRecvOrigDstAddr int
}

func IPv4() IPFamily {
	return IPFamily{
		Name:       "ipv4",
		UDPAddress: "udp4",
		TCPAddress: "tcp4",
		Localhost:  "127.0.0.1",

		SocketOptsFamily:          socketOptsFamilyIPv4,
		SocketOptsTransparent:     socketOptsTransparentIPv4,
		SocketOptsRecvOrigDstAddr: socketOptsRecvOrigDstAddrIPv4,
	}
}

func IPv6() IPFamily {
	return IPFamily{
		Name:       "ipv6",
		UDPAddress: "udp6",
		TCPAddress: "tcp6",
		Localhost:  "::1",

		SocketOptsFamily:          socketOptsFamilyIPv6,
		SocketOptsTransparent:     socketOptsTransparentIPv6,
		SocketOptsRecvOrigDstAddr: socketOptsRecvOrigDstAddrIPv6,
	}
}
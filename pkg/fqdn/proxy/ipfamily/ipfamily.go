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

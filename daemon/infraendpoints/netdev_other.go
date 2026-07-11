// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package infraendpoints

import "net"

// getCiliumHostIPsFromNetDev returns the router IPs configured on the given host
// device. This reads addresses via Linux netlink and is not available on other
// platforms, so it returns no addresses.
func getCiliumHostIPsFromNetDev(devName string) (ipv4GW, ipv6Router net.IP) {
	return nil, nil
}

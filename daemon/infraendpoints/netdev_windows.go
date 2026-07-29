// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package infraendpoints

import "net"

// getCiliumHostIPsFromNetDev returns no addresses on non-Linux platforms, where
// the cilium_host network device managed via netlink does not exist.
func getCiliumHostIPsFromNetDev(devName string) (ipv4GW, ipv6Router net.IP) {
	return nil, nil
}

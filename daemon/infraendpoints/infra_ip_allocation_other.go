// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package infraendpoints

import (
	"context"
	"net"
)

// waitForENI waits for an ENI device with the given MAC to appear. ENI device
// discovery relies on Linux netlink and is a no-op on other platforms.
func (r *infraIPAllocator) waitForENI(ctx context.Context, macAddr string) error {
	return nil
}

// removeOldRouterState clears stale IPs from the cilium_host device. This relies
// on Linux netlink and is a no-op on other platforms.
func (r *infraIPAllocator) removeOldRouterState(ipv6 bool, restoredIP net.IP) error {
	return nil
}

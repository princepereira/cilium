// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipam

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// removeUnreachableRoute deletes the unreachable route installed for the given
// IP from the main routing table. ESRCH is ignored as it means the entry was
// already deleted.
func removeUnreachableRoute(ip net.IP) error {
	err := netlink.RouteDel(&netlink.Route{
		Dst:   &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Table: unix.RT_TABLE_MAIN,
		Type:  unix.RTN_UNREACHABLE,
	})
	if err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipam

import (
	"errors"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// delUnreachableRoute deletes the unreachable route for the given IP. An
// already-deleted route (ESRCH) is treated as success.
func delUnreachableRoute(parsedIP net.IP) error {
	err := netlink.RouteDel(&netlink.Route{
		Dst:   &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(32, 32)},
		Table: unix.RT_TABLE_MAIN,
		Type:  unix.RTN_UNREACHABLE,
	})
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipam

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// cleanupUnreachableRoutes removes all unreachable routes for the given prefix.
// This is only needed if EnableUnreachableRoutes has been set.
func cleanupUnreachableRoutes(prefix netip.Prefix) error {
	var family int
	switch prefixFamily(prefix) {
	case IPv4:
		family = netlink.FAMILY_V4
	case IPv6:
		family = netlink.FAMILY_V6
	default:
		return errors.New("unknown cidr family")
	}

	routes, err := safenetlink.RouteListFiltered(family, &netlink.Route{
		Table: unix.RT_TABLE_MAIN,
		Type:  unix.RTN_UNREACHABLE,
	}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
	if err != nil {
		return fmt.Errorf("failed to fetch unreachable routes: %w", err)
	}

	var errs error
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		routePrefix, ok := netipx.FromStdIPNet(route.Dst)
		if !ok {
			continue
		}
		if !containsPrefix(prefix, routePrefix) {
			continue
		}

		err = netlink.RouteDel(&route)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			// We ignore ESRCH, as it means the entry was already deleted
			errs = errors.Join(errs, fmt.Errorf("failed to delete unreachable route for %s: %w",
				route.Dst.String(), err),
			)
		}
	}
	return errs
}

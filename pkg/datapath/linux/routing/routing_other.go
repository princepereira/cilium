// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linuxrouting

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

var errUnsupportedOp = fmt.Errorf("linux routing operations not supported on this platform")

// Configure is not supported on non-Linux platforms. Configuring per-ENI rules
// and routes relies on netlink, which is only available on Linux.
func (info *RoutingInfo) Configure(ip netip.Addr, mtu int, host bool) error {
	return errUnsupportedOp
}

// ReconcileGatewayRoutes is not supported on non-Linux platforms.
func (info *RoutingInfo) ReconcileGatewayRoutes(mtu int, rx statedb.ReadTxn, routes statedb.Table[*tables.Route]) (*statedb.WatchSet, error) {
	return nil, errUnsupportedOp
}

// Delete is not supported on non-Linux platforms.
func Delete(logger *slog.Logger, ip netip.Addr) error {
	return errUnsupportedOp
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linuxrouting

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

var errUnsupportedRoutingOp = fmt.Errorf("linux routing operations are not supported on this platform")

func (info *RoutingInfo) Configure(ip net.IP, mtu int, host bool) error {
	return errUnsupportedRoutingOp
}

func (info *RoutingInfo) ReconcileGatewayRoutes(mtu int, rx statedb.ReadTxn, routes statedb.Table[*tables.Route]) (*statedb.WatchSet, error) {
	return statedb.NewWatchSet(), errUnsupportedRoutingOp
}

func Delete(logger *slog.Logger, ip netip.Addr) error {
	return errUnsupportedRoutingOp
}

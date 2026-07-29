// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linuxrouting

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

var errNotSupported = errors.New("linux routing is not supported on this platform")

// Configure is not supported on non-Linux platforms.
func (info *RoutingInfo) Configure(ip netip.Addr, mtu int, host bool) error {
	return errNotSupported
}

// ReconcileGatewayRoutes is not supported on non-Linux platforms.
func (info *RoutingInfo) ReconcileGatewayRoutes(mtu int, rx statedb.ReadTxn, routes statedb.Table[*tables.Route]) (*statedb.WatchSet, error) {
	return nil, errNotSupported
}

// Delete is not supported on non-Linux platforms.
func Delete(logger *slog.Logger, ip netip.Addr) error {
	return errNotSupported
}

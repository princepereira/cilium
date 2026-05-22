// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package linuxrouting

import (
	"log/slog"
	"net"
	"net/netip"
	"strconv"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/mac"
)

type RoutingInfo struct {
	logger          *slog.Logger
	Gateway         net.IP
	CIDRs           []net.IPNet
	MasterIfMAC     mac.MAC
	Masquerade      bool
	InterfaceNumber int
	IpamMode        string
}

func (info *RoutingInfo) GetCIDRs() []net.IPNet { return info.CIDRs }

func NewRoutingInfo(logger *slog.Logger, gateway string, cidrs []string, macAddr, ifaceNum, ipamMode string, masquerade bool) (*RoutingInfo, error) {
	parsedCIDRs := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, c, err := net.ParseCIDR(cidr); err == nil && c != nil {
			parsedCIDRs = append(parsedCIDRs, *c)
		}
	}
	iface, _ := strconv.Atoi(ifaceNum)
	parsedMAC, _ := mac.ParseMAC(macAddr)
	return &RoutingInfo{logger: logger, Gateway: net.ParseIP(gateway), CIDRs: parsedCIDRs, MasterIfMAC: parsedMAC, Masquerade: masquerade, InterfaceNumber: iface, IpamMode: ipamMode}, nil
}

func (info *RoutingInfo) Configure(net.IP, int, bool) error { return nil }

func (info *RoutingInfo) ReconcileGatewayRoutes(int, statedb.ReadTxn, statedb.Table[*tables.Route]) (*statedb.WatchSet, error) {
	return statedb.NewWatchSet(), nil
}

func Delete(*slog.Logger, netip.Addr) error { return nil }

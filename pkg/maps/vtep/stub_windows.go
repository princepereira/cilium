// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package vtep

import (
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MaxEntries = 32
	MapName    = "cilium_vtep_map"
)

type Map interface {
	Update(newCIDR *cidr.CIDR, newTunnelEndpoint net.IP, vtepMAC mac.MAC) error
	Delete(tunnelEndpoint net.IP) error
	Dump(hash map[string][]string) error
}

type Key struct { IP types.IPv4 `align:"vtep_ip"` }
func (k *Key) String() string { return "" }

type VtepEndpointInfo struct {
	VtepMAC        mac.Uint64MAC `align:"vtep_mac"`
	TunnelEndpoint types.IPv4    `align:"tunnel_endpoint"`
}

type vtepMap struct{}

func newMap(*slog.Logger, *metrics.Registry) *vtepMap { return &vtepMap{} }
func LoadVTEPMap(*slog.Logger) Map                    { return &vtepMap{} }
func (m *vtepMap) init() error                        { return nil }
func (m *vtepMap) close() error                       { return nil }
func (m *vtepMap) Update(*cidr.CIDR, net.IP, mac.MAC) error { return nil }
func (m *vtepMap) Delete(net.IP) error                     { return nil }
func (m *vtepMap) Dump(map[string][]string) error         { return nil }

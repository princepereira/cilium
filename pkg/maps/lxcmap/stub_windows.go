// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package lxcmap

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	MaxEntries       = 65535
	EndpointFlagHost = 1
)

type Map interface {
	WriteEndpoint(f EndpointFrontend) error
	SyncHostEntry(addr netip.Addr) (bool, error)
	DeleteEntry(addr netip.Addr) error
	DeleteElement(logger *slog.Logger, f EndpointFrontend) []error
	Dump(hash map[string][]string) error
	DumpToMap() (map[netip.Addr]EndpointInfo, error)
}

type EndpointFrontend interface {
	LXCMac() mac.MAC
	GetNodeMAC() mac.MAC
	GetIfIndex() int
	GetParentIfIndex() int
	GetID() uint64
	GetRTInfo() (uint32, types.RTInfoEncoding)
	IPv4Address() netip.Addr
	IPv6Address() netip.Addr
	GetIdentity() identity.NumericIdentity
	IsAtHostNS() bool
	SkipMasqueradeV4() bool
	SkipMasqueradeV6() bool
}

type EndpointInfo struct {
	LxcID uint16
	Flags uint32
}

func (v *EndpointInfo) IsHost() bool { return v.Flags&EndpointFlagHost != 0 }

type lxcMap struct{ bpfMap *bpf.Map }

func newMap(*metrics.Registry) *lxcMap                                 { return &lxcMap{bpfMap: &bpf.Map{}} }
func OpenMap(*slog.Logger) (Map, error)                                { return &lxcMap{}, nil }
func (m *lxcMap) init() error                                          { return nil }
func (m *lxcMap) close() error                                         { return nil }
func (m *lxcMap) WriteEndpoint(EndpointFrontend) error                 { return nil }
func (m *lxcMap) SyncHostEntry(netip.Addr) (bool, error)               { return false, nil }
func (m *lxcMap) DeleteEntry(netip.Addr) error                         { return nil }
func (m *lxcMap) DeleteElement(*slog.Logger, EndpointFrontend) []error { return nil }
func (m *lxcMap) Dump(map[string][]string) error                       { return nil }
func (m *lxcMap) DumpToMap() (map[netip.Addr]EndpointInfo, error)      { return map[netip.Addr]EndpointInfo{}, nil }

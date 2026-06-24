// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package nodemap

import (
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/types"
)

const (
	MapNameV2         = "cilium_node_map_v2"
	DefaultMaxEntries = 16384
)

type MapV2 interface {
	Update(ip netip.Addr, nodeID uint16, SPI uint8) error
	Delete(ip netip.Addr) error
	IterateWithCallback(cb NodeIterateCallbackV2) error
	Size() uint32
}

type NodeKey struct {
	Family uint8
	IP     types.IPv6
}

type NodeValueV2 struct {
	NodeID uint16
	SPI    uint8
	Pad    uint8
}

type NodeIterateCallbackV2 func(*NodeKey, *NodeValueV2)

type nodeMapV2 struct{ conf Config }

func newMapV2(*slog.Logger, string, Config) *nodeMapV2 { return &nodeMapV2{} }
func LoadNodeMapV2(*slog.Logger) (MapV2, error)        { return &nodeMapV2{}, nil }
func (m *nodeMapV2) Update(netip.Addr, uint16, uint8) error { return nil }
func (m *nodeMapV2) Delete(netip.Addr) error                { return nil }
func (m *nodeMapV2) IterateWithCallback(NodeIterateCallbackV2) error { return nil }
func (m *nodeMapV2) Size() uint32                           { return DefaultMaxEntries }
func (m *nodeMapV2) init() error                            { return nil }
func (m *nodeMapV2) close() error                           { return nil }

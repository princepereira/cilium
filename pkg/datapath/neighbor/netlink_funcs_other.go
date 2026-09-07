// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package neighbor

import (
	"net"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"
)

// routeGetOptions mirrors the fields of netlink.RouteGetOptions used by the
// neighbor calculator. On non-Linux platforms the netlink type is unavailable.
type routeGetOptions struct {
	OifIndex int
	FIBMatch bool
}

// Neighbor flags mirror the Linux netlink NTF_*/NUD_* values. They are unused
// on non-Linux platforms but kept so shared code compiles.
const (
	ntfUse        = 0x01
	ntfExtLearned = 0x10
	ntfExtManaged = 0x00000001
	nudStale      = 0x04
)

// disabledNetlinkFuncs is a no-op [netlinkFuncs] used on non-Linux platforms,
// where neighbor programming via netlink is unavailable.
type disabledNetlinkFuncs struct{}

func (disabledNetlinkFuncs) RouteGetWithOptions(destination net.IP, options *routeGetOptions) ([]netlink.Route, error) {
	return nil, nil
}
func (disabledNetlinkFuncs) NeighSet(neigh *netlink.Neigh) error { return nil }
func (disabledNetlinkFuncs) NeighDel(neigh *netlink.Neigh) error { return nil }

func newNetlinkFuncsGetter(lifecycle cell.Lifecycle) *netlinkFuncsGetter {
	return &netlinkFuncsGetter{funcs: disabledNetlinkFuncs{}}
}

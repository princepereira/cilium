// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package neighbor

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// routeGetOptions aliases the Linux netlink route lookup options.
type routeGetOptions = netlink.RouteGetOptions

// Neighbor flags used by the reconciler.
const (
	ntfUse        = netlink.NTF_USE
	ntfExtLearned = netlink.NTF_EXT_LEARNED
	ntfExtManaged = netlink.NTF_EXT_MANAGED
	nudStale      = netlink.NUD_STALE
)

var _ netlinkFuncs = (*netlink.Handle)(nil)

func newNetlinkFuncsGetter(lifecycle cell.Lifecycle) *netlinkFuncsGetter {
	n := &netlinkFuncsGetter{}

	lifecycle.Append(
		cell.Hook{
			OnStart: func(_ cell.HookContext) error {
				// Get a netlink handle in the current namespace.
				// Otherwise we default to the namespace at startup. Which is not what we want
				// during testing where we might currently be in a sub-namespace.
				handle, err := safenetlink.NewHandle(nil)
				if err != nil {
					return fmt.Errorf("creating netlink handle: %w", err)
				}

				n.funcs = handle
				return nil
			},
		},
	)

	return n
}

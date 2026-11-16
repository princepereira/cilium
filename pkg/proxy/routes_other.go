// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package proxy

import "context"

// ReinstallRoutingRules is a no-op on non-Linux platforms. The real
// implementation programs Linux routing rules and tables to route packets to
// and from the L7 proxy, which relies on netlink and is Linux-only.
func (p *Proxy) ReinstallRoutingRules(ctx context.Context, mtu int, ipsecEnabled, wireguardEnabled bool) error {
	return nil
}

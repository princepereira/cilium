// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package proxy

import "context"

// ReinstallRoutingRules ensures the presence of routing rules and tables needed
// to route packets to and from the L7 proxy. The proxy routing rules are
// implemented with Linux netlink routing and are a no-op on other platforms.
func (p *Proxy) ReinstallRoutingRules(ctx context.Context, mtu int, ipsecEnabled, wireguardEnabled bool) error {
	return nil
}

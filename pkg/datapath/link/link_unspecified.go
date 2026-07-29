// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package link

import (
	"context"

	"github.com/vishvananda/netlink"
)

// Interface alternative names are a Linux-only netlink feature.
func addAltName(link netlink.Link, altName string) error {
	return netlink.ErrNotImplemented
}

// SyncCache is a no-op on non-Linux platforms: there is no netlink link table
// to enumerate (interfaces are managed via HNS on Windows), so the ifindex
// cache stays empty rather than failing the periodic sync job.
func (c *LinkCache) SyncCache(_ context.Context) error {
	return nil
}

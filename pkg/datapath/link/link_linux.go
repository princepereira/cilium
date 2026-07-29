// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package link

import (
	"context"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

func addAltName(link netlink.Link, altName string) error {
	return netlink.LinkAddAltName(link, altName)
}

// SyncCache refreshes the ifindex->name cache from the kernel's link list.
func (c *LinkCache) SyncCache(_ context.Context) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return err
	}

	indexToName := make(map[int]string, len(links))
	for _, link := range links {
		indexToName[link.Attrs().Index] = link.Attrs().Name
	}

	c.mu.Lock()
	c.indexToName = indexToName
	c.mu.Unlock()
	return nil
}

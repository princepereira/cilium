// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package link

import (
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// AddAltName sets the altnames for a link.
func AddAltName(linkName, altName string) error {
	link, err := safenetlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	return netlink.LinkAddAltName(link, altName)
}

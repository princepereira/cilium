// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package link

import "github.com/vishvananda/netlink"

func addAltName(link netlink.Link, altName string) error {
	return netlink.LinkAddAltName(link, altName)
}

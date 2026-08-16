// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package link

import "github.com/vishvananda/netlink"

// AddAltName is not supported outside Linux: the netlink library provides no
// LinkAddAltName implementation on non-Linux platforms.
func AddAltName(linkName, altName string) error {
	return netlink.ErrNotImplemented
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package mtu

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	nlFamilyAll = netlink.FAMILY_ALL
	nlFamilyV4  = netlink.FAMILY_V4
	nlFamilyV6  = netlink.FAMILY_V6

	rtnhFlagLinkDown = unix.RTNH_F_LINKDOWN
	rtnhFlagDead     = unix.RTNH_F_DEAD
)

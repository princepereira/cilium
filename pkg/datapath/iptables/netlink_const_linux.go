// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package iptables

import "github.com/vishvananda/netlink"

const (
	nlFamilyV4 = netlink.FAMILY_V4
	nlFamilyV6 = netlink.FAMILY_V6
)

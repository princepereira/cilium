// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// Package sysabi exposes a small, dependency-light set of Linux networking
// constants (address families and route next-hop flags) used by shared Cilium
// code. On Linux the values are sourced from netlink / x/sys/unix so they stay
// in lockstep with the platform. On non-Linux platforms the same constants are
// provided as literals with their well-known Linux ABI values, allowing shared
// files to compile without golang.org/x/sys/unix (which is empty off Linux).
package sysabi

import (
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// FamilyAll matches netlink.FAMILY_ALL.
	FamilyAll = netlink.FAMILY_ALL
	// FamilyV4 matches netlink.FAMILY_V4 (AF_INET).
	FamilyV4 = netlink.FAMILY_V4
	// FamilyV6 matches netlink.FAMILY_V6 (AF_INET6).
	FamilyV6 = netlink.FAMILY_V6

	// RTNHFDead matches unix.RTNH_F_DEAD.
	RTNHFDead = unix.RTNH_F_DEAD
	// RTNHFLinkDown matches unix.RTNH_F_LINKDOWN.
	RTNHFLinkDown = unix.RTNH_F_LINKDOWN

	// RTTableMain matches unix.RT_TABLE_MAIN.
	RTTableMain = unix.RT_TABLE_MAIN
	// RTNUnreachable matches unix.RTN_UNREACHABLE.
	RTNUnreachable = unix.RTN_UNREACHABLE
	// MSGTrunc matches unix.MSG_TRUNC.
	MSGTrunc = unix.MSG_TRUNC

	// ScopeLink matches netlink.SCOPE_LINK.
	ScopeLink = netlink.SCOPE_LINK
)

const (
	// IFFSlave matches unix.IFF_SLAVE.
	IFFSlave = unix.IFF_SLAVE
)

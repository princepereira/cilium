// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package sysabi

// Linux networking ABI constants provided as literals on non-Linux platforms.
// Values mirror the Linux kernel UAPI and netlink's address-family aliases.
const (
	// FamilyAll matches netlink.FAMILY_ALL.
	FamilyAll = 0
	// FamilyV4 matches netlink.FAMILY_V4 (AF_INET).
	FamilyV4 = 2
	// FamilyV6 matches netlink.FAMILY_V6 (AF_INET6).
	FamilyV6 = 10

	// RTNHFDead matches unix.RTNH_F_DEAD.
	RTNHFDead = 0x1
	// RTNHFLinkDown matches unix.RTNH_F_LINKDOWN.
	RTNHFLinkDown = 0x10

	// RTTableMain matches unix.RT_TABLE_MAIN.
	RTTableMain = 0xfe
	// RTNUnreachable matches unix.RTN_UNREACHABLE.
	RTNUnreachable = 0x7
	// MSGTrunc matches unix.MSG_TRUNC.
	MSGTrunc = 0x20

	// ScopeLink matches netlink.SCOPE_LINK (RT_SCOPE_LINK).
	ScopeLink = 0xfd
)

const (
	// IFFSlave matches unix.IFF_SLAVE.
	IFFSlave = 0x800
)

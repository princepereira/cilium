// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipsec

import "github.com/vishvananda/netlink"

// These functions inspect Linux XFRM state/policy objects, which have no
// equivalent on non-Linux platforms (netlink.XfrmState/XfrmPolicy are empty
// structs there). They are provided as no-ops so the package still builds; the
// real implementations live in utils.go behind the linux build tag.

func CountUniqueIPsecKeys(states []netlink.XfrmState) (int, error) {
	return 0, nil
}

func IsDecryptState(state netlink.XfrmState) bool {
	return false
}

func CountXfrmStatesByDir(states []netlink.XfrmState) (int, int) {
	return 0, 0
}

func CountXfrmPoliciesByDir(states []netlink.XfrmPolicy) (int, int, int) {
	return 0, 0, 0
}

func GetSPIFromXfrmPolicy(policy *netlink.XfrmPolicy) uint8 {
	return 0
}

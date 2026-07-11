// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipsec

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const (
	// DefaultReqID is the default reqid used for all IPSec rules.
	DefaultReqID = 1
)

func CountUniqueIPsecKeys(states []netlink.XfrmState) (int, error) {
	return 0, fmt.Errorf("not supported on this platform")
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

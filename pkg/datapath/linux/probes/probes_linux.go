// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package probes

import "github.com/vishvananda/netlink"

// Family type definitions
const (
	NTF_EXT_LEARNED = netlink.NTF_EXT_LEARNED
	NTF_EXT_MANAGED = netlink.NTF_EXT_MANAGED
)

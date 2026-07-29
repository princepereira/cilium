// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipfamily

// The transparent-proxy socket options are Linux-specific and have no
// equivalent on other platforms. They are defined as zero so that the package
// still builds; the tproxy datapath that consumes them is only wired up on
// Linux.
const (
	sockoptIPv4Family          = 0
	sockoptIPv4Transparent     = 0
	sockoptIPv4RecvOrigDstAddr = 0

	sockoptIPv6Family          = 0
	sockoptIPv6Transparent     = 0
	sockoptIPv6RecvOrigDstAddr = 0
)

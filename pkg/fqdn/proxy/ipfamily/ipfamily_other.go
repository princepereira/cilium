// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipfamily

// Transparent proxy socket options are Linux-specific. They are defined here
// as zero values so the package builds on non-Linux platforms where the
// transparent proxy datapath is not available.
const (
	socketOptsFamilyIPv4          = 0
	socketOptsTransparentIPv4     = 0
	socketOptsRecvOrigDstAddrIPv4 = 0

	socketOptsFamilyIPv6          = 0
	socketOptsTransparentIPv6     = 0
	socketOptsRecvOrigDstAddrIPv6 = 0
)
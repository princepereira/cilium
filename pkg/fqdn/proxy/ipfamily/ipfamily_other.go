// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipfamily

// Socket option constants are Linux-specific. On non-Linux platforms these
// transparent-proxy socket options are not available, so they are defined as
// zero values to allow the package to build.
const (
	solIP               = 0
	ipTransparent       = 0
	ipRecvOrigDstAddr   = 0
	solIPv6             = 0
	ipv6Transparent     = 0
	ipv6RecvOrigDstAddr = 0
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipsec

// ProbeXfrmStateOutputMask reports that XFRM state output masks are unavailable
// outside Linux.
func ProbeXfrmStateOutputMask() error {
	return errIPsecUnsupported
}

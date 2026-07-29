// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cmd

// probeXfrmStateOutputMask is a no-op on non-Linux platforms, where IPsec/xfrm
// is not supported.
func probeXfrmStateOutputMask() error {
	return nil
}

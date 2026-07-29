// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import "github.com/cilium/cilium/pkg/datapath/linux/ipsec"

// probeXfrmStateOutputMask probes for kernel support of xfrm state output
// masks, which IPsec-with-tunneling relies on (Linux 4.19+).
func probeXfrmStateOutputMask() error {
	return ipsec.ProbeXfrmStateOutputMask()
}

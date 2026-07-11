// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package connector

import "github.com/cilium/cilium/pkg/datapath/linux/sysctl"

// DisableRpFilter tries to disable rpfilter on specified interface.
func DisableRpFilter(sysctl sysctl.Sysctl, ifName string) error {
	return sysctl.Disable([]string{"net", "ipv4", "conf", ifName, "rp_filter"})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package connector

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
)

// DisableRpFilter is not supported on non-Linux platforms.
func DisableRpFilter(sysctl sysctl.Sysctl, ifName string) error {
	return fmt.Errorf("not supported on this platform")
}

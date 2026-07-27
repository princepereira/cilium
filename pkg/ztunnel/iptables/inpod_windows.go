// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package iptables

import (
	"fmt"
	"log/slog"
	"runtime"
)

// ztunnel inpod mode relies on Linux iptables and policy routing, neither of
// which exist on Windows. These operations are therefore not supported.

// CreateInPodRules is not supported on Windows.
func CreateInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	return fmt.Errorf("ztunnel inpod rules are not supported on %s", runtime.GOOS)
}

// DeleteInPodRules is not supported on Windows.
func DeleteInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	return fmt.Errorf("ztunnel inpod rules are not supported on %s", runtime.GOOS)
}

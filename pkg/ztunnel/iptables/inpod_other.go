// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package iptables

import "log/slog"

// CreateInPodRules is a no-op on non-Linux platforms where iptables-based
// in-pod redirection rules are not available.
func CreateInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	return nil
}

// DeleteInPodRules is a no-op on non-Linux platforms where iptables-based
// in-pod redirection rules are not available.
func DeleteInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	return nil
}

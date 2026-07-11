// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package iptables

import (
	"fmt"
	"log/slog"
)

var errUnsupportedInPodOp = fmt.Errorf("ztunnel in-pod iptables operations are not supported on this platform")

func CreateInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	return errUnsupportedInPodOp
}

func DeleteInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	return errUnsupportedInPodOp
}

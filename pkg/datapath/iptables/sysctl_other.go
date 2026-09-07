// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package iptables

import "github.com/cilium/cilium/pkg/datapath/linux/sysctl"

// enableIPForwarding on non-Linux platforms is a no-op. It just exists
// to make compilation possible.
func enableIPForwarding(_ sysctl.Sysctl, _ bool) error {
	return nil
}

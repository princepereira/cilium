// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import "github.com/cilium/cilium/pkg/datapath/linux/sysctl"

// enableIPForwarding on Windows is a no-op. It exists to make compilation
// possible; IP forwarding is managed by the host networking stack.
func enableIPForwarding(_ sysctl.Sysctl, _ bool) error {
	return nil
}

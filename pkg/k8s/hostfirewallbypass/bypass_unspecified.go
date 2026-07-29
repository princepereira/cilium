// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package hostfirewallbypass

import "syscall"

// The SO_MARK based host-firewall/DNS-proxy bypass is a Linux-only mechanism.
// On other platforms the dialer control is a no-op.
func setProxyEgressMark(network, address string, c syscall.RawConn) error {
	return nil
}

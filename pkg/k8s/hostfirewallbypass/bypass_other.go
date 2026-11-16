// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package hostfirewallbypass

import "syscall"

// setProxyEgressMark is a no-op on non-Linux platforms. Setting SO_MARK to
// bypass the host firewall and DNS proxy is Linux-only.
func setProxyEgressMark(network, address string, c syscall.RawConn) error {
	return nil
}

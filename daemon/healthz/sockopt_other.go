// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package healthz

import "syscall"

// setsockoptReuseAddrAndPort sets the SO_REUSEADDR and SO_REUSEPORT socket
// options on Linux. These options are configured via Linux-specific syscalls, so
// this is a no-op on other platforms.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package healthz

import "syscall"

// setsockoptReuseAddrAndPort is a no-op on platforms that do not expose the
// SO_REUSEADDR/SO_REUSEPORT socket options via golang.org/x/sys/unix.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	return nil
}

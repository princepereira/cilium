// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package healthz

import "syscall"

// setsockoptReuseAddrAndPort is a no-op on non-Linux platforms where the
// SO_REUSEPORT socket option is not available.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	return nil
}

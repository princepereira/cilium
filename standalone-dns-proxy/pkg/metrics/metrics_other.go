// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package metrics

import "syscall"

// setsockoptReusePort is a no-op on non-Linux platforms. SO_REUSEPORT is
// Linux-only.
func setsockoptReusePort(network, address string, c syscall.RawConn) error {
	return nil
}

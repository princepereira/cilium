// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package api

import "syscall"

// setsockoptReuseAddrAndPort is a no-op on non-Linux platforms. SO_REUSEPORT
// is Linux-only.
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	return nil
}

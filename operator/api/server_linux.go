// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package api

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// setsockoptReuseAddrAndPort sets SO_REUSEADDR and SO_REUSEPORT
func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		// Allow reuse of recently-used addresses. This socket option is
		// set by default on listeners in Go's net package, see
		// net setDefaultListenerSockopts
		if err := unix.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			soerr = fmt.Errorf("failed to setsockopt(SO_REUSEADDR): %w", err)
			return
		}

		// Allow reuse of recently-used ports. This gives the operator a
		// better chance to re-bind upon restarts.
		soerr = unix.SetsockoptInt(s, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return soerr
}

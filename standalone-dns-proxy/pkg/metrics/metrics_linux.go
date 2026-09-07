// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package metrics

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// setsockoptReusePort sets SO_REUSEPORT on the socket to allow the new SDP pod
// to bind the metrics port while the old pod is still terminating during a
// surge-based rolling update.
func setsockoptReusePort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		if err := unix.SetsockoptInt(s, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			soerr = fmt.Errorf("failed to setsockopt(SO_REUSEPORT): %w", err)
		}
	}); err != nil {
		return err
	}
	return soerr
}

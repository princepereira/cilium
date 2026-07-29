// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package zds

import "golang.org/x/sys/unix"

// socketControlRights encodes a file descriptor as a socket control message
// (SCM_RIGHTS) so it can be passed to another process over a Unix domain socket.
func socketControlRights(fd int) []byte {
	return unix.UnixRights(fd)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package zds

import "golang.org/x/sys/unix"

// msgTruncated reports whether the given ReadMsgUnix flags indicate the
// message was truncated.
func msgTruncated(flags int) bool {
	return flags&unix.MSG_TRUNC != 0
}

// unixRights encodes a single file descriptor as a socket control message for
// SCM_RIGHTS-based FD passing over a Unix socket.
func unixRights(fd int) []byte {
	return unix.UnixRights(fd)
}

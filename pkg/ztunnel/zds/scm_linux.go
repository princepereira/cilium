// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package zds

import "golang.org/x/sys/unix"

// msgTrunc is the recvmsg flag indicating the received datagram was truncated.
const msgTrunc = unix.MSG_TRUNC

// socketControlRights encodes the given file descriptors as socket control
// message rights (SCM_RIGHTS) for passing over a unix domain socket.
func socketControlRights(fds ...int) []byte {
	return unix.UnixRights(fds...)
}

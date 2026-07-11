// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package zds

// msgTrunc mirrors the Linux recvmsg MSG_TRUNC flag. The ZDS unix socket
// protocol is Linux-only, so this is a no-op value on other platforms.
const msgTrunc = 0

// socketControlRights encodes file descriptors as SCM_RIGHTS control messages.
// File descriptor passing over unix sockets is Linux-only, so this returns nil
// on other platforms.
func socketControlRights(fds ...int) []byte {
	return nil
}

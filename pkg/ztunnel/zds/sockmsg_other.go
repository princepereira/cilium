// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package zds

// msgTruncated reports whether the given ReadMsgUnix flags indicate the
// message was truncated. Non-Linux platforms do not expose MSG_TRUNC.
func msgTruncated(flags int) bool {
	return false
}

// unixRights is a no-op on non-Linux platforms where SCM_RIGHTS-based FD
// passing is not available.
func unixRights(fd int) []byte {
	return nil
}

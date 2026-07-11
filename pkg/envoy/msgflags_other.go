// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package envoy

// msgTrunc mirrors the Linux recvmsg MSG_TRUNC flag. Truncation detection is a
// Linux-only concern for the access log unix socket, so this is a no-op value
// on other platforms.
const msgTrunc = 0

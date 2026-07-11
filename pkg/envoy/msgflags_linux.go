// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package envoy

import "golang.org/x/sys/unix"

// msgTrunc is the recvmsg flag indicating the received datagram was truncated.
const msgTrunc = unix.MSG_TRUNC

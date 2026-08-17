// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package envoy

// msgTrunc mirrors unix.MSG_TRUNC (0x20) on non-Linux platforms.
const msgTrunc = 0x20

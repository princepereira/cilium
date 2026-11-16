// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package translation

// These constants configure Envoy listener socket options. Envoy runs on Linux
// nodes, so the Linux TCP_KEEP* values are used on all platforms. They are
// defined here as literals because these socket-option constants are not
// available in the syscall package on non-Linux platforms.
const (
	tcpKeepIdle  = 0x4 // syscall.TCP_KEEPIDLE on Linux
	tcpKeepIntvl = 0x5 // syscall.TCP_KEEPINTVL on Linux
	tcpKeepCnt   = 0x6 // syscall.TCP_KEEPCNT on Linux
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package translation

import "syscall"

// These constants configure Envoy listener socket options. Envoy runs on Linux
// nodes, so the Linux values are authoritative regardless of the platform the
// operator is built for.
const (
	tcpKeepIdle  = syscall.TCP_KEEPIDLE
	tcpKeepIntvl = syscall.TCP_KEEPINTVL
	tcpKeepCnt   = syscall.TCP_KEEPCNT
)

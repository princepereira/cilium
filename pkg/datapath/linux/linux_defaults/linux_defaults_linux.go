// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux_defaults

import "golang.org/x/sys/unix"

// rtProtoKernel is the routing protocol identifier used when installing fib
// rules and routes so that systemd-networkd does not interfere with them.
const rtProtoKernel = unix.RTPROT_KERNEL

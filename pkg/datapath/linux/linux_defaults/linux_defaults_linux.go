// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux_defaults

import "golang.org/x/sys/unix"

// rtProtoKernel is the RTPROT_KERNEL routing protocol identifier.
const rtProtoKernel = unix.RTPROT_KERNEL
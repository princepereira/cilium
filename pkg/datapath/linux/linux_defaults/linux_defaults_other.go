// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linux_defaults

// rtProtoKernel mirrors the Linux RTPROT_KERNEL routing protocol identifier so
// the package builds on non-Linux platforms.
const rtProtoKernel = 2
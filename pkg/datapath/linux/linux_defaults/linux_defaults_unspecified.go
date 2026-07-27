// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package linux_defaults

// rtProtoKernel mirrors the Linux RTPROT_KERNEL value (2). It is only
// meaningful for the Linux datapath but is defined here so the package builds
// on all platforms.
const rtProtoKernel = 2

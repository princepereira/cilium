// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package xdp

import "github.com/cilium/ebpf/link"

// AttachFlags is the XDP attach flags type. On Linux it aliases the flag type
// from github.com/cilium/ebpf/link.
type AttachFlags = link.XDPAttachFlags

const (
	attachFlagDriverMode  = link.XDPDriverMode
	attachFlagGenericMode = link.XDPGenericMode
)

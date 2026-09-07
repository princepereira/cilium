// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package xdp

// AttachFlags is the XDP attach flags type. Outside Linux the flag type from
// github.com/cilium/ebpf/link is unavailable, so it is defined locally with the
// same underlying representation and values.
type AttachFlags uint32

const (
	// attachFlagGenericMode mirrors link.XDPGenericMode (XDP_FLAGS_SKB_MODE).
	attachFlagGenericMode AttachFlags = 1 << 1
	// attachFlagDriverMode mirrors link.XDPDriverMode (XDP_FLAGS_DRV_MODE).
	attachFlagDriverMode AttachFlags = 1 << 2
)

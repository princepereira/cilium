// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package linux_defaults

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestRTProtoMatchesKernel guards the non-Linux fallback value in
// rtproto_other.go against drift from the kernel's RTPROT_KERNEL.
func TestRTProtoMatchesKernel(t *testing.T) {
	if RTProto != unix.RTPROT_KERNEL {
		t.Fatalf("RTProto = %d, want RTPROT_KERNEL = %d", RTProto, unix.RTPROT_KERNEL)
	}
	if unix.RTPROT_KERNEL != 2 {
		t.Fatalf("RTPROT_KERNEL = %d, update rtproto_other.go fallback to match", unix.RTPROT_KERNEL)
	}
}

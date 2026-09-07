// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package bpf

// applyLegacyMapAlias is a no-op on non-Windows platforms. Linux shares maps
// between the control plane and datapath by bpffs pin path and does not carry
// the eBPF-for-Windows datapath name/version skew.
func (m *Map) applyLegacyMapAlias() {}

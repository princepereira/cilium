// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

// mapBatchAPISupported reports whether the BPF map batch lookup API
// (BPF_MAP_LOOKUP_BATCH) is available on this platform. It is supported by the
// Linux kernel.
const mapBatchAPISupported = true

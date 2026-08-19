// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bpf

// mapBatchAPISupported reports whether the BPF map batch lookup API
// (BPF_MAP_LOOKUP_BATCH) is available on this platform. The eBPF-for-Windows
// runtime does not implement the batch API, so iteration falls back to the
// per-key NextKey/Lookup path.
const mapBatchAPISupported = false

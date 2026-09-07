// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package signalmap

// Record mirrors perf.Record for platforms where the perf ring buffer reader is
// not available. It carries the fields used by the signal subsystem.
type Record struct {
	// CPU is the CPU this record was generated on.
	CPU int

	// RawSample is the data submitted via bpf_perf_event_output.
	RawSample []byte

	// LostSamples is the number of samples which could not be output because
	// the ring buffer was full.
	LostSamples uint64

	// Remaining is the minimum number of bytes remaining in the per-CPU buffer
	// after this Record has been read.
	Remaining int
}

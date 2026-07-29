// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ebpfperf

import (
	"os"
	"sync"

	"github.com/cilium/ebpf"
)

// Record mirrors the fields of perf.Record used by Cilium. On Windows the perf
// subsystem is unavailable, so records are never produced.
type Record struct {
	CPU         int
	RawSample   []byte
	LostSamples uint64
}

// Reader is a no-op perf reader for Windows. It never yields records: Read
// blocks until the reader is closed, matching the "no events" semantics of a
// platform without a BPF perf ring buffer.
type Reader struct {
	done      chan struct{}
	closeOnce sync.Once
}

// NewReader returns a no-op reader. The map argument is ignored.
func NewReader(_ *ebpf.Map, _ int) (*Reader, error) {
	return &Reader{done: make(chan struct{})}, nil
}

// Read blocks until Close is called and then reports os.ErrClosed.
func (r *Reader) Read() (Record, error) {
	<-r.done
	return Record{}, os.ErrClosed
}

// Pause is a no-op.
func (r *Reader) Pause() error { return nil }

// Resume is a no-op.
func (r *Reader) Resume() error { return nil }

// Close unblocks any pending Read and releases resources.
func (r *Reader) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	return nil
}

// IsUnknownEvent always reports false on Windows.
func IsUnknownEvent(_ error) bool { return false }

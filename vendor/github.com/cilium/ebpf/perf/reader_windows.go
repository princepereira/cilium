// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

//go:build windows

package perf

import (
	"errors"
	"time"

	"github.com/cilium/ebpf"
)

// This file provides a compile-only stub of the perf reader API for Windows.
// perf event rings are a Linux-only feature; the real implementation lives in
// reader.go / ring.go (//go:build !windows). These stubs allow packages that
// reference the perf API to build on Windows, returning errors at runtime.

var errNotSupported = errors.New("perf reader is not supported on this platform")

// Record contains either a sample or a counter of the number of lost samples.
type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64

	// The minimum number of bytes remaining in the per-CPU buffer after this
	// Record has been read. Negative for overwritable buffers.
	Remaining int
}

// ReaderOptions control the behaviour of a Reader.
type ReaderOptions struct {
	WakeupEvents int
	Watermark    int
	Overwritable bool
}

// Reader allows reading bpf_perf_event_output from user space.
type Reader struct{}

// NewReader is not supported on Windows and returns an error at runtime.
func NewReader(array *ebpf.Map, perCPUBuffer int) (*Reader, error) {
	return nil, errNotSupported
}

// NewReaderWithOptions is not supported on Windows and returns an error at runtime.
func NewReaderWithOptions(array *ebpf.Map, perCPUBuffer int, opts ReaderOptions) (*Reader, error) {
	return nil, errNotSupported
}

// Close is a no-op on Windows.
func (pr *Reader) Close() error { return errNotSupported }

// SetDeadline is a no-op on Windows.
func (pr *Reader) SetDeadline(t time.Time) {}

// Read is not supported on Windows and returns an error at runtime.
func (pr *Reader) Read() (Record, error) { return Record{}, errNotSupported }

// ReadInto is not supported on Windows and returns an error at runtime.
func (pr *Reader) ReadInto(rec *Record) error { return errNotSupported }

// Pause is not supported on Windows and returns an error at runtime.
func (pr *Reader) Pause() error { return errNotSupported }

// Resume is not supported on Windows and returns an error at runtime.
func (pr *Reader) Resume() error { return errNotSupported }

// BufferSize returns zero on Windows.
func (pr *Reader) BufferSize() int { return 0 }

// Flush is not supported on Windows and returns an error at runtime.
func (pr *Reader) Flush() error { return errNotSupported }

// IsUnknownEvent returns false on Windows.
func IsUnknownEvent(err error) bool { return false }

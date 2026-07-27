// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

// This is a Cilium-provided compile-only stub of the perf package for Windows.
// The Linux perf ring-buffer machinery has no Windows equivalent, so the types
// and functions here exist only so that packages consuming perf records can be
// built for GOOS=windows. All operations return ErrNotSupported at runtime.

package perf

import (
	"errors"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

var (
	// ErrClosed is returned when operating on a closed Reader.
	ErrClosed = os.ErrClosed
	// ErrFlushed is returned when a Read is interrupted by a call to Flush.
	ErrFlushed = errors.New("flushed")

	errNotSupported = errors.New("perf events are not supported on Windows")
)

// Record contains either a sample or a counter of the number of lost samples.
type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	RawSample []byte

	// The number of samples which could not be output, since the ring buffer was full.
	LostSamples uint64

	// The minimum number of bytes remaining in the per-CPU buffer after this Record has been read.
	Remaining int
}

// ReaderOptions control the behaviour of the perf reader.
type ReaderOptions struct {
	Watermark    int
	Overwritable bool
}

// Reader is a stub perf reader for Windows.
type Reader struct{}

// NewReader is not supported on Windows.
func NewReader(array *ebpf.Map, perCPUBuffer int) (*Reader, error) {
	return nil, errNotSupported
}

// NewReaderWithOptions is not supported on Windows.
func NewReaderWithOptions(array *ebpf.Map, perCPUBuffer int, opts ReaderOptions) (*Reader, error) {
	return nil, errNotSupported
}

// Close is a no-op on Windows.
func (pr *Reader) Close() error { return nil }

// SetDeadline is a no-op on Windows.
func (pr *Reader) SetDeadline(t time.Time) {}

// Read is not supported on Windows.
func (pr *Reader) Read() (Record, error) { return Record{}, errNotSupported }

// ReadInto is not supported on Windows.
func (pr *Reader) ReadInto(rec *Record) error { return errNotSupported }

// Pause is a no-op on Windows.
func (pr *Reader) Pause() error { return nil }

// Resume is a no-op on Windows.
func (pr *Reader) Resume() error { return nil }

// BufferSize returns zero on Windows.
func (pr *Reader) BufferSize() int { return 0 }

// Flush is a no-op on Windows.
func (pr *Reader) Flush() error { return nil }

// IsUnknownEvent always returns false on Windows.
func IsUnknownEvent(err error) bool { return false }

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package signalmap

import (
	"os"
	"sync"
)

// open is a no-op on non-Linux platforms. The signal map is backed by a perf
// event ring buffer (PerfEventArray), which eBPF-for-Windows does not support,
// so no BPF map is created. The datapath programs that emit these signals are
// not loaded on Windows, so there is nothing to receive.
func (sm *signalMap) open() error {
	return nil
}

// noopReader is a PerfReader that never yields any records. Read blocks until
// Close is called, at which point it returns os.ErrClosed so the signal
// manager's read loop exits cleanly.
type noopReader struct {
	once   sync.Once
	closed chan struct{}
}

func (r *noopReader) Read() (Record, error) {
	<-r.closed
	return Record{}, os.ErrClosed
}

func (r *noopReader) Pause() error  { return nil }
func (r *noopReader) Resume() error { return nil }

func (r *noopReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}

// NewReader returns a no-op reader on non-Linux platforms so the signal manager
// starts successfully and simply never receives datapath signals.
func (sm *signalMap) NewReader() (PerfReader, error) {
	return &noopReader{closed: make(chan struct{})}, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package signalmap

import (
	"os"

	"github.com/cilium/hive/cell"
)

const MapName = "cilium_signals"

var Cell = cell.Module("signal-map", "eBPF map signal passes wakeup events from Cilium datapath", cell.Provide(func() Map { return &signalMap{} }))

type Record struct {
	RawSample   []byte
	LostSamples uint64
}

type PerfReader interface {
	Read() (Record, error)
	Pause() error
	Resume() error
	Close() error
}

type Map interface {
	NewReader() (PerfReader, error)
	MapName() string
}

type signalMap struct{}
type perfReader struct{}

func (signalMap) NewReader() (PerfReader, error) { return perfReader{}, nil }
func (signalMap) MapName() string                { return MapName }
func (perfReader) Read() (Record, error)         { return Record{}, os.ErrClosed }
func (perfReader) Pause() error                  { return nil }
func (perfReader) Resume() error                 { return nil }
func (perfReader) Close() error                  { return nil }

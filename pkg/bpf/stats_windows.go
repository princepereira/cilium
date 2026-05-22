// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"github.com/cilium/cilium/pkg/time"
)

// DumpStats tracks statistics over the dump of a map.
type DumpStats struct {
	Started            time.Time
	Finished           time.Time
	Lookup             uint32
	LookupFailed       uint32
	PrevKeyUnavailable uint32
	KeyFallback        uint32
	MaxEntries         uint32
	Interrupted        uint32
	Completed          bool
}

// NewDumpStats returns a new stats structure for collecting dump statistics.
func NewDumpStats(m *Map) *DumpStats {
	return &DumpStats{
		MaxEntries: m.MaxEntries(),
	}
}

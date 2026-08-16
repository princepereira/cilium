// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package signalmap

import (
	"os"

	"github.com/cilium/ebpf/perf"
)

func (sm *signalMap) NewReader() (PerfReader, error) {
	return perf.NewReader(sm.ebpfMap, os.Getpagesize())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package signalmap

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/cilium/cilium/pkg/bpf"
)

func (sm *signalMap) open() error {
	if err := sm.oldBpfMap.Create(); err != nil {
		return err
	}
	path := bpf.MapPath(sm.logger, MapName)

	var err error
	sm.ebpfMap, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (sm *signalMap) NewReader() (PerfReader, error) {
	return perf.NewReader(sm.ebpfMap, os.Getpagesize())
}

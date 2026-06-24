// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package ipcache

import (
	"sync"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

func newIPCacheMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&Key{},
		&RemoteEndpointInfo{},
		MaxEntries,
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG)
}

// NewMap instantiates a Map.
func NewMap(registry *metrics.Registry, name string) *Map {
	return &Map{
		Map: *newIPCacheMap(name).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

var (
	// IPCache is a mapping of all endpoint IPs in the cluster which this
	// Cilium agent is a part of to their corresponding security identities.
	// It is a singleton; there is only one such map per agent.
	ipcache *Map
	once    = &sync.Once{}
)

// IPCacheMap gets the ipcache Map singleton. If it has not already been done,
// this also initializes the Map.
func IPCacheMap(registry *metrics.Registry) *Map {
	once.Do(func() {
		ipcache = NewMap(registry, Name)
	})
	return ipcache
}

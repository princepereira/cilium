// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package eventsmap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

func newEventsMap(lifecycle cell.Lifecycle) bpf.MapOut[Map] {
	eventsMap := &eventsMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				return fmt.Errorf("failed to get number of possible CPUs: %w", err)
			}
			err = eventsMap.init(cpus)
			if err != nil {
				return fmt.Errorf("initializing events map: %w", err)
			}
			return nil
		},
		OnStop: func(context cell.HookContext) error {
			// We don't currently care for cleaning up.
			return nil
		},
	})

	return bpf.NewMapOut(Map(eventsMap))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package eventsmap

import (
	"github.com/cilium/cilium/pkg/bpf"
)

// newEventsMap provides a nil events map on non-Linux platforms. The cilium
// events map is a PerfEventArray, which is not supported by eBPF-for-Windows.
// Consumers such as the monitor agent already handle a nil eventsmap.Map by
// operating in agent-events-only mode.
func newEventsMap() bpf.MapOut[Map] {
	return bpf.NewMapOut(Map(nil))
}

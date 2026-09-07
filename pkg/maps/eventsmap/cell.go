// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventsmap

import (
	"github.com/cilium/hive/cell"
)

// Cell provides eventsmap.Map, which is the hive representation of the cilium
// events perf event ring buffer.
var Cell = cell.Module(
	"events-map",
	"eBPF ring buffer of cilium events",

	cell.Provide(newEventsMap),
)

var (
	MaxEntries int
)

type Map any

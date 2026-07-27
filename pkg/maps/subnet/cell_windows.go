// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package subnet

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
)

// Cell manages subnet routing information for hybrid routing mode.
//
// On non-Linux platforms the subnet BPF map and its reconciler are not
// available. This variant provides only the StateDB table (and its read-only
// view) so that cross-platform consumers (e.g. the subnet watcher) can be
// constructed. Subnet entries are tracked but never programmed into a BPF map.
var Cell = cell.Module(
	"subnet-map",
	"Manages the subnet to identity table",

	cell.Provide(
		newSubnetEntryTable,
		statedb.RWTable[SubnetTableEntry].ToTable,
	),
)

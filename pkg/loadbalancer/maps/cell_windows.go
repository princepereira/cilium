// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the Windows CNC-based LBMaps implementation.
var Cell = cell.Module(
	"loadbalancer-maps",
	"Load-balancing CNC maps (Windows)",

	cell.Provide(newCNCLBMaps),
)

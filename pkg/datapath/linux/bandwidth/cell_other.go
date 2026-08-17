// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bandwidth

import "github.com/cilium/hive/cell"

// Cell is a no-op on non-Linux platforms. The real bandwidth manager programs
// tc/EDT qdiscs via netlink, which is Linux-only.
var Cell = cell.Module(
	"bandwidth-manager",
	"Linux Bandwidth Manager for EDT-based pacing (no-op on non-Linux)",
)

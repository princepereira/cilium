// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package datapath

import (
	"github.com/cilium/hive/cell"
)

// Cell provides the datapath module on non-Linux platforms.
//
// The Linux datapath (see cells.go) wires together a large set of BPF- and
// netlink-based subsystems that only build and run on Linux. On other
// platforms (e.g. Windows) those subsystems are not available, so this cell
// intentionally provides a minimal datapath. Native, platform-specific
// datapath functionality (e.g. via HNS/HCS on Windows) is wired in
// incrementally through dedicated *_windows.go implementations.
var Cell = cell.Module(
	"datapath",
	"Datapath",
)

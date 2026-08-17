// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package stats

import "github.com/cilium/hive/cell"

// Cell is a no-op on non-Linux platforms. BPF program statistics collection
// relies on the cilium/ebpf link query API, cgroup program enumeration, and
// TC filter listing, all of which are Linux-only.
var Cell = cell.Module(
	"bpf-stats",
	"BPF Stats commands (no-op on non-Linux)",
)

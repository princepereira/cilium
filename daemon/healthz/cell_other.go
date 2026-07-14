// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package healthz

import "github.com/cilium/hive/cell"

// Cell on non-Linux platforms only exposes the agent health endpoint. The
// kube-proxy replacement health endpoint depends on the BPF load-balancer
// datapath (BPFOps, device tables) which is Linux-only, so it is omitted here.
var Cell = cell.Group(
	// Agent Healthz
	agentHealthzCell,
)

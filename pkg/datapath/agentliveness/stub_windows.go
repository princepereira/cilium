// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package agentliveness

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"agent-liveness-updater",
	"Agent Liveness Updater",
)

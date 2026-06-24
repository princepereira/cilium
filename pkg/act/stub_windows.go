// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package act

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"act-metrics",
	"Metrics with counts of new and active connections for each service-zone pair",
)

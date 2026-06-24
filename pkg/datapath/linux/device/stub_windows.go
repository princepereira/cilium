// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package device

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"device-reconciler",
	"Windows stub",
)

var TableCell = cell.Module(
	"device-reconciler-table",
	"Windows stub",
)

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bwmap

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"bwmap",
	"Manages the endpoint bandwidth limit BPF map",
)

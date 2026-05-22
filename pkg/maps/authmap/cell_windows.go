// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package authmap

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"auth-map",
	"eBPF map which manages authenticated connections between identities",
)

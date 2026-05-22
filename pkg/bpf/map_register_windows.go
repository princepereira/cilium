// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"log/slog"

	"github.com/cilium/cilium/api/v1/models"
)

// GetMap returns the Map registered with the specified name. Stub on Windows.
func GetMap(logger *slog.Logger, name string) *Map {
	return nil
}

// GetOpenMaps returns a list of all open BPF maps. Stub on Windows.
func GetOpenMaps() []*models.BPFMap {
	return nil
}

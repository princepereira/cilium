// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ebpf

import (
	"github.com/cilium/cilium/api/v1/models"
)

// GetOpenMaps returns all open BPF maps (stub on Windows).
func GetOpenMaps() []*models.BPFMap {
	return nil
}

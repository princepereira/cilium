// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package maps

import "github.com/cilium/ebpf"

// LoadMapSpecs returns no datapath map specs on Windows.
func LoadMapSpecs() (map[string]*ebpf.MapSpec, error) {
	return map[string]*ebpf.MapSpec{}, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package loadinfo

import "github.com/mackerelio/go-osstat/memory"

// LogCurrentSystemLoad logs basic memory statistics. Per-process CPU/memory
// accounting relies on /proc and is only available on Linux, so it is omitted
// on other platforms.
func LogCurrentSystemLoad(logFunc LogFunc) {
	memInfo, err := memory.Get()
	if err == nil {
		logFunc("Memory: Total: %d Used: %d (%.2f%%) Free: %d",
			toMB(memInfo.Total), toMB(memInfo.Used), toPercent(memInfo.Used, memInfo.Total), toMB(memInfo.Free))
	}
}
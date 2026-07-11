// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"os"
	"syscall"
)

// peakRSS returns the peak resident set size (in kilobytes) of the finished
// process, as reported by the kernel via getrusage(2).
func peakRSS(state *os.ProcessState) (int64, bool) {
	if state == nil {
		return 0, false
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0, false
	}
	return usage.Maxrss, true
}

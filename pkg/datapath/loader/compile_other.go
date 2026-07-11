// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package loader

import "os"

// peakRSS is not available on non-Linux platforms.
func peakRSS(state *os.ProcessState) (int64, bool) {
	return 0, false
}

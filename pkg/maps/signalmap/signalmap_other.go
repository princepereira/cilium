// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package signalmap

import "fmt"

// NewReader is not supported on non-Linux platforms. The perf event ring buffer
// reader is only available on Linux.
func (sm *signalMap) NewReader() (PerfReader, error) {
	return nil, fmt.Errorf("signal map perf reader not supported on this platform")
}

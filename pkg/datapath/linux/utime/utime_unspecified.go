// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package utime

import "github.com/cilium/cilium/pkg/time"

// getBoottime returns the system boot time. The Linux implementation derives
// this from /proc/stat and the monotonic/boottime clocks, neither of which is
// available on other platforms, so this is a best-effort approximation using
// the current wall-clock time.
func getBoottime() (time.Time, error) {
	return time.Now(), nil
}

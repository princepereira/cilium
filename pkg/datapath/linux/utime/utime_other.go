// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package utime

import (
	"github.com/cilium/cilium/pkg/time"
)

// getBoottime is a no-op on non-Linux platforms. Parsing the kernel boot time
// relies on /proc/stat and the boottime/monotonic clocks, which are
// Linux-specific. The utime offset is only consumed by the Linux datapath, so
// returning a zero time (offset 0) without an error avoids logging spurious
// errors while keeping the controller inert.
func getBoottime() (time.Time, error) {
	return time.Time{}, nil
}

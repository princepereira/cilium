// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package utime

import (
	"fmt"

	"github.com/cilium/cilium/pkg/time"
)

// getBoottime is not supported on non-Linux platforms. Parsing the kernel boot
// time relies on /proc/stat and the boottime/monotonic clocks, which are
// Linux-specific.
func getBoottime() (time.Time, error) {
	return time.Time{}, fmt.Errorf("getBoottime not supported on this platform")
}

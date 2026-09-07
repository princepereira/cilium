// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// GetMtime returns monotonic time that can be used to compare
// values with ktime_get_ns() BPF helper, e.g. needed to check
// the timeout in sec for BPF entries. We return the raw nsec,
// although that is not quite usable for comparison. Go has
// runtime.nanotime() but doesn't expose it as API.
func GetMtime() (uint64, error) {
	var ts unix.Timespec

	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0, fmt.Errorf("Unable get time: %w", err)
	}

	return uint64(unix.TimespecToNsec(ts)), nil
}

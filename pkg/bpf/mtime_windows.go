// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procQueryUnbiasedInterrupt = kernel32.NewProc("QueryUnbiasedInterruptTime")
)

// GetMtime returns monotonic time in nanoseconds that can be used to compare
// values with the ktime_get_ns() BPF helper, e.g. to check the timeout for BPF
// entries. On Windows this uses QueryUnbiasedInterruptTime, which returns a
// monotonic, sleep-unbiased timestamp since boot in 100ns units, matching the
// CLOCK_MONOTONIC semantics used on Linux.
func GetMtime() (uint64, error) {
	// QueryUnbiasedInterruptTime writes the current unbiased interrupt time
	// (in 100-nanosecond units) into the provided uint64.
	var interruptTime uint64
	ret, _, err := procQueryUnbiasedInterrupt.Call(uintptr(unsafe.Pointer(&interruptTime)))
	if ret == 0 {
		return 0, fmt.Errorf("QueryUnbiasedInterruptTime failed: %w", err)
	}

	// Convert 100ns units to nanoseconds.
	return interruptTime * 100, nil
}

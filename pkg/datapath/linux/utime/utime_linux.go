// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package utime

import (
	"bufio"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/time"
)

// getBoottime returns the kernel boot time.
// We parse it from /proc/stat. GetBoottime() should be invoked only occasionally.
func getBoottime() (t time.Time, err error) {
	var boottime int64
	var delta int64
	stat, err := os.Open(btimeInfoFilepath)
	if err != nil {
		return t, err
	}
	defer stat.Close()
	scanner := bufio.NewScanner(stat)
	for scanner.Scan() {
		n, _ := fmt.Sscanf(scanner.Text(), "btime %d\n", &boottime)
		if n == 1 {
			break
		}
	}
	err = scanner.Err()
	if err != nil {
		return t, err
	}

	// get an estimated difference between monotonic and boot clocks, that accounts for
	// the lost suspend time in the monotonic clock.
	// Linux 5.8 has bpf helper for ktime_get_boot_ns that does not need this, so we can
	// get rid of this block when Linux 5.8 is the oldest supported kernel.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Keep the minimum difference out of 10 samples to estimate the drift between boottime and
	// monotonic clocks at the time this call.
	for range nClockSamples {
		var monotonicTimespec unix.Timespec
		err = unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonicTimespec)
		if err != nil {
			return t, err
		}
		var bootTimespec unix.Timespec
		err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTimespec)
		if err != nil {
			return t, err
		}
		bNano := bootTimespec.Nano()
		mNano := monotonicTimespec.Nano()
		if bNano > mNano {
			diff := bNano - mNano
			if delta == int64(0) || diff < delta {
				delta = diff
			}
		}
	}
	return time.Unix(boottime, delta), nil
}

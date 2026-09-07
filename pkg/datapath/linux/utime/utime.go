// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utime

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/time"
)

const (
	btimeInfoFilepath = "/proc/stat"
	nClockSamples     = 10

	// Number of bits to shift a monotonic 64-bit nanosecond clock for utime unit.  Dividing
	// nanoseconds by 2^9 yields roughly half microsecond accuracy but avoids expensive 64-bit
	// divisions in the datapath.  With this shift the range of an u64 is ~300000 years
	// instead of ~600 years if left at nanoseconds.
	// With this shift full seconds can be multiplied by 1e9>>9 to get utime units.
	// Must be kept in sync with `UTIME_SHIFT` in datapath (bpf/lib/utime.h), any changes to
	// this will have an upgrade impact.
	utimeShift = 9
	// 10^9 has 9 trailing zeroes also in binary, so they can be shifted off without any loss
	// of accuracy.
	secsToUtimeMultiplier = 1_000_000_000 >> utimeShift // integer value (1953125)
	// utime numerical limits in seconds
	minSeconds = 0
	maxSeconds = 1 << (64 + utimeShift) / 1_000_000_000 // 2^(64+9)/10^9
)

// Unix epoch time value on 2^9/10^9 second accuracy. This accuracy
// is chosen so that the timing is reasonably accurate for expiry times, but does not require 64-bit
// division of a monotonic clock value in the datapath, as it is a rather slow operation.
type UTime uint64

func ToUTime(secs int64, nanos int) UTime {
	return UTime(secs)*secsToUtimeMultiplier + UTime(nanos)>>utimeShift
}

func TimeToUTime(t time.Time) UTime {
	return ToUTime(t.Unix(), t.Nanosecond())
}

func (t UTime) Time() time.Time {
	secs := t / secsToUtimeMultiplier
	usecs := t % secsToUtimeMultiplier
	return time.Unix(int64(secs), int64(usecs<<utimeShift))
}

func (t UTime) String() string {
	return t.Time().String()
}

type utimeController struct {
	logger    *slog.Logger
	configMap configmap.Map
	offset    UTime
}

func (u *utimeController) sync(_ context.Context) error {
	offset := getCurrentUTimeOffset(u.logger)
	if offset != u.offset {
		if err := u.configMap.Update(configmap.UTimeOffset, uint64(offset)); err != nil {
			return fmt.Errorf("failed to update utime offset: %w", err)
		}
		u.offset = offset
	}
	return nil
}

// getCurrentUTimeOffset returns the current time offset to be configured for the datapath
func getCurrentUTimeOffset(logger *slog.Logger) UTime {
	// boottime is in seconds since Unix epoch, delta is clock drift in nanoseconds
	boottime, err := getBoottime()
	if err != nil {
		logger.Error("Error getting boot time from file",
			logfields.File, btimeInfoFilepath,
			logfields.Error, err,
		)
	}
	return TimeToUTime(boottime)
}

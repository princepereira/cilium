// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadinfo

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// backgroundInterval is the interval in which system load information is logged
	backgroundInterval = 5 * time.Second

	// cpuWatermark is the minimum percentage of CPU to have a process
	// listed in the log
	cpuWatermark = 1.0
)

// LogFunc is the function to used to log the system load
type LogFunc func(format string, args ...any)

func toMB(total uint64) uint64 {
	return total / 1024 / 1024
}

func toPercent(part uint64, total uint64) float64 {
	return float64(part) / float64(total) * 100
}

// LogPeriodicSystemLoad logs the system load in the interval specified until
// the given ctx is canceled.
func LogPeriodicSystemLoad(ctx context.Context, logFunc LogFunc, interval time.Duration) {
	go func() {
		LogCurrentSystemLoad(logFunc)

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				LogCurrentSystemLoad(logFunc)
			}
		}
	}()
}

// StartBackgroundLogger starts background logging
func StartBackgroundLogger(logger *slog.Logger) {
	l := logger.With(logfields.Type, "background")
	ctx := context.Background()
	logFunc := LogFunc(func(format string, args ...any) {
		if l.Enabled(ctx, slog.LevelDebug) {
			l.Debug(fmt.Sprintf(format, args...))
		}
	})
	LogPeriodicSystemLoad(ctx, logFunc, backgroundInterval)
}

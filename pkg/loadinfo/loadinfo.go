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
)

// LogFunc is the function to used to log the system load
type LogFunc func(format string, args ...any)

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

package cncapi

import (
	"context"
	"log/slog"
)

// logger is the package-level logger used for CNC API call tracing.
// Consumers can replace it via SetLogger.
var logger *slog.Logger = slog.Default()

// SetLogger allows consumers to set a custom slog.Logger for CNC API call tracing.
// If nil is passed, logging is effectively disabled (uses a no-op handler).
func SetLogger(l *slog.Logger) {
	if l == nil {
		logger = slog.New(discardHandler{})
		return
	}
	logger = l
}

// discardHandler is a slog.Handler that discards all log records.
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (d discardHandler) WithAttrs(_ []slog.Attr) slog.Handler       { return d }
func (d discardHandler) WithGroup(_ string) slog.Handler             { return d }

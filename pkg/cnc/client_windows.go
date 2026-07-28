// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

// Package cnc bridges Cilium's typed BPF map writes to the native Windows
// eBPF datapath exposed by cncapi.dll (github.com/princepereira/cncshim).
//
// The client is created lazily and degrades gracefully: if cncapi.dll (or the
// underlying CNC kernel components) are not present, or the process is not
// elevated, the client stays disabled and every helper becomes a no-op. This
// keeps cilium-agent buildable and startable on developer machines that lack
// the CNC runtime, while automatically activating on properly provisioned
// Windows nodes.
package cnc

import (
	"log/slog"
	"net/netip"
	"sync"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

var (
	initOnce sync.Once
	client   cncapi.CNCApi
	logger   atomicLogger
)

// atomicLogger allows a logger to be installed before the (lazy) client init
// runs, without importing the hive. A nil logger falls back to slog.Default.
type atomicLogger struct {
	mu sync.RWMutex
	l  *slog.Logger
}

func (a *atomicLogger) get() *slog.Logger {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.l != nil {
		return a.l
	}
	return slog.Default()
}

func (a *atomicLogger) set(l *slog.Logger) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.l = l
}

// SetLogger installs the logger used for CNC diagnostics. Optional; if unset,
// slog.Default is used.
func SetLogger(l *slog.Logger) { logger.set(l) }

// ensureClient performs the one-time attempt to load cncapi.dll. On failure it
// logs a warning and leaves the client nil so all helpers no-op.
func ensureClient() cncapi.CNCApi {
	initOnce.Do(func() {
		c, err := cncapi.New()
		if err != nil {
			logger.get().Warn("CNC datapath (cncapi.dll) unavailable; "+
				"Windows BPF map writes will not be mirrored to the native datapath",
				"error", err,
			)
			return
		}
		client = c
		logger.get().Info("CNC datapath (cncapi.dll) initialized; "+
			"mirroring Windows BPF map writes to the native eBPF runtime",
			"version", cncapi.ShimVersion.String(),
		)
	})
	return client
}

// Enabled reports whether the CNC datapath is active. It triggers lazy init.
func Enabled() bool { return ensureClient() != nil }

// SetIdentity mirrors an ipcache entry (CIDR -> security identity) into the
// CNC datapath. No-op when the datapath is unavailable.
func SetIdentity(subnet netip.Prefix, identity uint32) error {
	c := ensureClient()
	if c == nil {
		return nil
	}
	return c.SetIdentity(subnet, identity)
}

// DeleteIdentity removes an ipcache entry from the CNC datapath. No-op when the
// datapath is unavailable.
func DeleteIdentity(subnet netip.Prefix) error {
	c := ensureClient()
	if c == nil {
		return nil
	}
	return c.DeleteIdentity(subnet)
}

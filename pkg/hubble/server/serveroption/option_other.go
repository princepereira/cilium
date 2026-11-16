// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package serveroption

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
)

// WithUnixSocketListener configures a unix domain socket listener with the
// given file path. On non-Linux platforms the Linux-specific ownership and
// permission handling is skipped.
func WithUnixSocketListener(scopedLog *slog.Logger, path string) Option {
	return func(o *Options) error {
		if o.Listener != nil {
			return fmt.Errorf("listener already configured")
		}
		socketPath := strings.TrimPrefix(path, "unix://")
		os.Remove(socketPath)
		socket, err := net.Listen("unix", socketPath)
		if err != nil {
			return err
		}
		o.Listener = socket
		return nil
	}
}

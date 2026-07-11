// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Copyright Authors of Cilium

//go:build !linux

package serveroption

import (
	"fmt"
	"net"
	"os"
	"strings"

	"log/slog"
)

// WithUnixSocketListener configures a unix domain socket listener with the
// given file path. The Linux-specific socket ownership/permission handling is
// not available on non-Linux platforms, so this variant only sets up the
// listener.
func WithUnixSocketListener(scopedLog *slog.Logger, path string) Option {
	return func(o *Options) error {
		if o.Listener != nil {
			return fmt.Errorf("listener already configured")
		}
		socketPath := strings.TrimPrefix(path, "unix://")
		_ = os.Remove(socketPath)
		socket, err := net.Listen("unix", socketPath)
		if err != nil {
			return err
		}
		o.Listener = socket
		return nil
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reconciler

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// SocketTerminationCell is the Windows placeholder for the socket-termination
// feature. On Linux this cell terminates UDP & TCP sockets connected to deleted
// backends using netlink INET_DIAG (see termination_linux.go). Neither
// INET_DIAG nor per-netns socket iteration exist on Windows; when the CNC
// datapath removes a backend it is responsible for resetting affected
// connections. This cell therefore only logs that the feature is unavailable.
var SocketTerminationCell = cell.Module(
	"socket-termination",
	"Terminates sockets connected to deleted backends - not implemented on Windows",

	cell.Invoke(func(log *slog.Logger) {
		log.Debug("Socket termination for deleted backends is not implemented on Windows; "+
			"relying on the CNC datapath to reset affected connections",
			logfields.LogSubsys, "socket-termination",
		)
	}),
)

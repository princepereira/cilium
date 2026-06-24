// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package listener

import "net"

// Version represents the version of the monitor listener.
type Version int

const (
	VersionUnsupported Version = iota
	Version1_2
)

// MonitorListener is the interface for monitor event listeners.
type MonitorListener interface {
	Enqueue(msg []byte)
	Version() Version
	Close()
	Conn() net.Conn
}

// IsDisconnected returns true if the error indicates a disconnected listener.
func IsDisconnected(err error) bool {
	return false
}

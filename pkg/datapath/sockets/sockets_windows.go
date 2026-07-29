// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

// This is a compile-only stub of the socket-diag based socket destroyer for
// non-Linux platforms. Destroying sockets relies on the Linux SOCK_DIAG /
// inet_diag netlink subsystem, which has no equivalent off Linux.

package sockets

import (
	"errors"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
)

var errNotSupported = errors.New("socket destroyer is not supported on this platform")

// State filter masks. Values are placeholders on non-Linux platforms.
var (
	StateFilterTCP uint32 = 0xffff
	StateFilterUDP uint32 = 0xffff
)

// DestroySocketCB is an optional callback to decide whether a socket should be
// destroyed.
type DestroySocketCB func(id netlink.SocketID) bool

// SocketFilter mirrors the Linux definition.
type SocketFilter struct {
	DestIp    net.IP
	DestPort  uint16
	Family    uint8
	Protocol  uint8
	States    uint32
	DestroyCB DestroySocketCB
}

// SocketDestroyer destroys sockets matching a filter.
type SocketDestroyer interface {
	Destroy(logger *slog.Logger, filter SocketFilter) error
}

type noopSocketDestroyer struct{}

func (noopSocketDestroyer) Destroy(logger *slog.Logger, filter SocketFilter) error {
	return errNotSupported
}

// NewSocketDestroyer returns a no-op destroyer on non-Linux platforms.
func NewSocketDestroyer(l *slog.Logger, sockRevNat4, sockRevNat6 *bpf.Map) (SocketDestroyer, error) {
	return noopSocketDestroyer{}, nil
}

// InetDiagDestroyEnabled reports that socket destruction is unsupported.
func InetDiagDestroyEnabled(logger *slog.Logger, probeTCP, probeUDP bool) error {
	return errNotSupported
}

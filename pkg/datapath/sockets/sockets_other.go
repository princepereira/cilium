// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package sockets

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
)

// The real socket-termination datapath relies on the Linux sock_diag netlink
// framework and BPF cgroup iterators, which have no equivalent on non-Linux
// platforms. This file provides the public surface so consumers still build.

func stateMask(ms ...int) uint32 {
	var out uint32
	for _, m := range ms {
		out |= 1 << m
	}
	return out
}

// StateFilterTCP is a mask of all TCP states considered for socket termination.
var StateFilterTCP = stateMask(
	netlink.TCP_ESTABLISHED,
	netlink.TCP_CLOSE_WAIT,
	netlink.TCP_FIN_WAIT1,
	netlink.TCP_FIN_WAIT2,
	netlink.TCP_SYN_RECV,
	netlink.TCP_NEW_SYN_REC,
	netlink.TCP_CLOSE,
	netlink.TCP_SYN_SENT,
	netlink.TCP_CLOSING,
	netlink.TCP_LAST_ACK,
	netlink.TCP_LISTEN,
)

// StateFilterUDP is a mask of all states considered for socket termination.
const StateFilterUDP = 0xffff

type SocketDestroyer interface {
	Destroy(logger *slog.Logger, filter SocketFilter) error
}

type SocketFilter struct {
	DestIp   netip.Addr
	DestPort uint16
	Family   uint8
	Protocol uint8
	States   uint32
	// Optional callback function to determine whether a filtered socket needs to be destroyed
	DestroyCB DestroySocketCB
}

type DestroySocketCB func(id netlink.SocketID) bool

// MatchSocket reports whether the given socket matches the filter. Mirrors the
// Linux implementation so cross-platform consumers can reference it.
func (f *SocketFilter) MatchSocket(socket netlink.SocketID) bool {
	socketAddr, ok := netip.AddrFromSlice(socket.Destination)
	if !ok {
		return false
	}
	if socketAddr.Unmap() == f.DestIp.Unmap() && socket.DestinationPort == f.DestPort {
		if f.DestroyCB == nil || f.DestroyCB(socket) {
			return true
		}
	}

	return false
}

// disabledSocketDestroyer is a no-op [SocketDestroyer].
type disabledSocketDestroyer struct{}

func (disabledSocketDestroyer) Destroy(logger *slog.Logger, filter SocketFilter) error {
	return nil
}

// NewSocketDestroyer returns a no-op destroyer on non-Linux platforms.
func NewSocketDestroyer(l *slog.Logger, sockRevNat4, sockRevNat6 *bpf.Map) (SocketDestroyer, error) {
	return disabledSocketDestroyer{}, nil
}

// InetDiagDestroyEnabled reports that inet_diag socket destruction is not
// available on non-Linux platforms.
func InetDiagDestroyEnabled(logger *slog.Logger, probeTCP, probeUDP bool) error {
	return fmt.Errorf("socket destruction via inet_diag is not supported on this platform")
}

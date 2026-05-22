// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package l2respondermap

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName           = "cilium_l2_responder_v4"
	DefaultMaxEntries = 4096
)

var Cell = cell.Provide(NewMap)

type Map interface {
	Create(ip netip.Addr, ifIndex uint32) error
	Lookup(ip netip.Addr, ifIndex uint32) (*L2ResponderStats, error)
	Delete(ip netip.Addr, ifIndex uint32) error
	IterateWithCallback(cb IterateCallback) error
}

func NewMap(cell.Lifecycle, *slog.Logger) Map {
	return NewFakeMap()
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a L2 responder map.
type IterateCallback func(*L2ResponderKey, *L2ResponderStats)

// L2ResponderKey implements the bpf.MapKey interface.
//
// Must be in sync with struct l2_responder_v4_key in <bpf/lib/l2_responder.h>
type L2ResponderKey struct {
	IP      types.IPv4 `align:"ip4"`
	IfIndex uint32     `align:"ifindex"`
}

func (k *L2ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", k.IP, k.IfIndex)
}

func newL2ResponderKey(ip netip.Addr, ifIndex uint32) L2ResponderKey {
	key := L2ResponderKey{IfIndex: ifIndex}
	key.IP.FromAddr(ip)
	return key
}

// L2ResponderStats implements the bpf.MapValue interface.
//
// Must be in sync with struct l2_responder_stats in <bpf/lib/l2_responder.h>
type L2ResponderStats struct {
	ResponsesSent uint64 `align:"responses_sent"`
}

func (s *L2ResponderStats) String() string {
	return fmt.Sprintf("responses_sent=%d", s.ResponsesSent)
}

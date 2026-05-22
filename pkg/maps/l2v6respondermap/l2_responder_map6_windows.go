// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package l2v6respondermap

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName           = "cilium_l2_responder_v6"
	DefaultMaxEntries = 4096
)

var Cell = cell.Provide(NewMap)

type Map interface {
	Create(ip netip.Addr, ifIndex uint32) error
	Lookup(ip netip.Addr, ifIndex uint32) (*l2respondermap.L2ResponderStats, error)
	Delete(ip netip.Addr, ifIndex uint32) error
	IterateWithCallback(cb IterateCallback) error
}

func NewMap(cell.Lifecycle, *slog.Logger) Map {
	return NewFakeMap()
}

func NewFakeMap() Map {
	return &fakeMap{entries: make(map[L2V6ResponderKey]l2respondermap.L2ResponderStats)}
}

type fakeMap struct {
	entries map[L2V6ResponderKey]l2respondermap.L2ResponderStats
}

func (fm *fakeMap) Create(ip netip.Addr, ifIndex uint32) error {
	fm.entries[newL2V6ResponderKey(ip, ifIndex)] = l2respondermap.L2ResponderStats{}
	return nil
}

func (fm *fakeMap) Lookup(ip netip.Addr, ifIndex uint32) (*l2respondermap.L2ResponderStats, error) {
	entry, found := fm.entries[newL2V6ResponderKey(ip, ifIndex)]
	if found {
		return &entry, nil
	}
	return nil, nil
}

func (fm *fakeMap) Delete(ip netip.Addr, ifIndex uint32) error {
	delete(fm.entries, newL2V6ResponderKey(ip, ifIndex))
	return nil
}

type IterateCallback func(*L2V6ResponderKey, *l2respondermap.L2ResponderStats)

func (fm *fakeMap) IterateWithCallback(cb IterateCallback) error {
	var key L2V6ResponderKey
	var val l2respondermap.L2ResponderStats
	for k, v := range fm.entries {
		key = k
		val = v
		cb(&key, &val)
	}
	return nil
}

type L2V6ResponderKey struct {
	IP      types.IPv6 `align:"ip6"`
	IfIndex uint32     `align:"ifindex"`
	Pad     uint32     `align:"pad"`
}

func (k *L2V6ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", k.IP, k.IfIndex)
}

func newL2V6ResponderKey(ip netip.Addr, ifIndex uint32) L2V6ResponderKey {
	return L2V6ResponderKey{
		IP:      types.IPv6(ip.As16()),
		IfIndex: ifIndex,
	}
}

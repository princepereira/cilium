// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package neighbor

import (
	"net/netip"

	"github.com/cilium/hive/cell"
)

var ForwardableIPCell = cell.Module("forwardable-ip", "Forwardable IP subsystem (unsupported on windows)")
var Cell = cell.Module("neighbor", "Neighbor subsystem (unsupported on windows)", ForwardableIPCell)

type ForwardableIPOwnerType int

const ForwardableIPOwnerNode ForwardableIPOwnerType = iota

type ForwardableIPOwner struct {
	Type ForwardableIPOwnerType
	ID   string
}

type ForwardableIPInitializer struct{}

type ForwardableIPManager struct{}

func (*ForwardableIPManager) RegisterInitializer(string) ForwardableIPInitializer { return ForwardableIPInitializer{} }
func (*ForwardableIPManager) FinishInitializer(ForwardableIPInitializer)          {}
func (*ForwardableIPManager) Insert(netip.Addr, ForwardableIPOwner) error         { return nil }
func (*ForwardableIPManager) Delete(netip.Addr, ForwardableIPOwner) error         { return nil }
func (*ForwardableIPManager) Enabled() bool                                       { return false }

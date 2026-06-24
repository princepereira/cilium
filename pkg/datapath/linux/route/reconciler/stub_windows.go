// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package reconciler

import (
	"errors"
	"net/netip"

	"github.com/cilium/hive/cell"
	statedbreconciler "github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

var Cell = cell.Module(
	"route-reconciler",
	"Windows stub",
)

var TableCell = cell.Module(
	"route-reconciler-table",
	"Windows stub",
)

type RouteReconcilerMetrics *statedbreconciler.ExpVarMetrics

type AdminDistance int

const AdminDistanceDefault AdminDistance = 100

type RouteOwner struct {
	name string
}

func (o *RouteOwner) String() string {
	if o == nil {
		return ""
	}
	return o.name
}

type TableID uint32

const (
	TableMain  TableID = 254
	TableLocal TableID = 255
)

type Scope uint8

const (
	SCOPE_UNIVERSE Scope = 0
	SCOPE_LINK     Scope = 253
)

type Type uint8

const (
	RTN_UNSPEC Type = 0x0
	RTN_LOCAL  Type = 0x2
)

type NexthopInfo struct {
	Device  *tables.Device
	Nexthop netip.Addr
}

type MultiPathInfo []*NexthopInfo

type DesiredRoute struct {
	Owner         *RouteOwner
	Table         TableID
	Prefix        netip.Prefix
	Priority      uint32
	AdminDistance AdminDistance
	Nexthop       netip.Addr
	Src           netip.Addr
	Device        *tables.Device
	MultiPath     MultiPathInfo
	MTU           uint32
	Scope         Scope
	Type          Type
}

var ErrOwnerDoesNotExist = errors.New("owner does not exist")

type Initializer struct{}

type DesiredRouteManager struct{}

func (*DesiredRouteManager) RegisterOwner(name string) (*RouteOwner, error) {
	return &RouteOwner{name: name}, nil
}

func (*DesiredRouteManager) GetOrRegisterOwner(name string) (*RouteOwner, error) {
	return &RouteOwner{name: name}, nil
}

func (*DesiredRouteManager) GetOwner(name string) (*RouteOwner, error) {
	return &RouteOwner{name: name}, nil
}

func (*DesiredRouteManager) RemoveOwner(*RouteOwner) error {
	return nil
}

func (*DesiredRouteManager) RegisterInitializer(string) Initializer {
	return Initializer{}
}

func (*DesiredRouteManager) FinalizeInitializer(Initializer) {}

func (*DesiredRouteManager) UpsertRoute(DesiredRoute) error {
	return nil
}

func (*DesiredRouteManager) UpsertRouteWait(DesiredRoute) error {
	return nil
}

func (*DesiredRouteManager) DeleteRoute(DesiredRoute) error {
	return nil
}

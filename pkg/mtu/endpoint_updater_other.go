// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package mtu

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/daemon/cmd/cni"
	"github.com/cilium/cilium/pkg/datapath/tables"
)

type endpointUpdaterParams struct {
	cell.In

	JobGroup    job.Group
	DB          *statedb.DB
	MTUTable    statedb.Table[RouteMTU]
	DeviceTable statedb.Table[*tables.Device]
	Logger      *slog.Logger
	MTUConfig   Config
	CNI         cni.CNIConfigManager
}

type EndpointMTUUpdater interface {
	RegisterHook(hook EndpointMTUUpdateHook)
}

type EndpointMTUUpdateHook func(routeMTUs []RouteMTU) error

type endpointUpdater struct{}

func newEndpointUpdater(p endpointUpdaterParams) EndpointMTUUpdater {
	return &endpointUpdater{}
}

func (emu *endpointUpdater) RegisterHook(hook EndpointMTUUpdateHook) {}

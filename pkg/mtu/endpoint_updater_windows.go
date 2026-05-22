// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package mtu

import (
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
	CNI         cni.CNIConfigManager
}

type EndpointMTUUpdater interface {
	RegisterHook(hook EndpointMTUUpdateHook)
}

type EndpointMTUUpdateHook func(routeMTUs []RouteMTU) error

type endpointUpdater struct{}

func newEndpointUpdater(endpointUpdaterParams) EndpointMTUUpdater { return &endpointUpdater{} }
func (*endpointUpdater) RegisterHook(EndpointMTUUpdateHook)       {}

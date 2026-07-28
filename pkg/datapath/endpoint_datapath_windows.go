// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package datapath

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	fakeiptables "github.com/cilium/cilium/pkg/datapath/iptables/fake"
	"github.com/cilium/cilium/pkg/datapath/loader"
	loaderTypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	endpointTypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

// endpointDatapathDepsOut bundles the datapath dependencies required to
// construct endpoints (see pkg/endpoint.EndpointParams). On Linux these are
// backed by eBPF maps and the program loader; on non-Linux platforms we
// provide non-functional stubs so the agent hive can be constructed and
// started. The policy map factory is provided separately by policymap.Cell
// (see cells_windows.go), backed by the in-memory BPF map implementation, so
// endpoint regeneration can open per-endpoint policy maps.
type endpointDatapathDepsOut struct {
	cell.Out

	Loader          loaderTypes.Loader
	Orchestrator    endpointTypes.Orchestrator
	CompilationLock loaderTypes.CompilationLock
	IPTablesManager iptables.Manager
	CTMapGC         ctmap.GCRunner
}

func newEndpointDatapathDeps() endpointDatapathDepsOut {
	return endpointDatapathDepsOut{
		Loader:          loader.NewLoader(),
		Orchestrator:    &fakeendpoint.FakeOrchestrator{},
		CompilationLock: loader.NewCompilationLock(),
		IPTablesManager: fakeiptables.NewManager(),
		CTMapGC:         ctmap.NewFakeGCRunner(),
	}
}

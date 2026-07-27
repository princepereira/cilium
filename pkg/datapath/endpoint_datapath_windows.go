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
	"github.com/cilium/cilium/pkg/maps/policymap"
)

// endpointDatapathDepsOut bundles the datapath dependencies required to
// construct endpoints (see pkg/endpoint.EndpointParams). On Linux these are
// backed by eBPF maps and the program loader; on non-Linux platforms we
// provide non-functional stubs so the agent hive can be constructed and
// started. Endpoint regeneration itself is not supported until a native
// (e.g. HNS-based) datapath is implemented.
type endpointDatapathDepsOut struct {
	cell.Out

	Loader          loaderTypes.Loader
	Orchestrator    endpointTypes.Orchestrator
	CompilationLock loaderTypes.CompilationLock
	IPTablesManager iptables.Manager
	CTMapGC         ctmap.GCRunner
	PolicyMapFactory policymap.Factory
}

func newEndpointDatapathDeps() endpointDatapathDepsOut {
	return endpointDatapathDepsOut{
		Loader:          loader.NewLoader(),
		Orchestrator:    &fakeendpoint.FakeOrchestrator{},
		CompilationLock: loader.NewCompilationLock(),
		IPTablesManager: fakeiptables.NewManager(),
		CTMapGC:         ctmap.NewFakeGCRunner(),
		PolicyMapFactory: nil,
	}
}

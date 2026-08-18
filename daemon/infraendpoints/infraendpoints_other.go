// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package infraendpoints

import (
	"context"

	"github.com/cilium/hive/cell"

	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
)

// InfraIPAllocator is responsible to create infra related IPs (router, ingress
// & health). The implementation is Linux-only; this declaration keeps the type
// available for cross-platform wiring.
type InfraIPAllocator interface {
	AllocateIPs(ctx context.Context) error
	GetHealthEndpointRouting() *linuxrouting.RoutingInfo
}

// Cell is a no-op on non-Linux platforms where netlink-based infrastructure
// endpoint setup is not available. It still provides a no-op InfraIPAllocator
// so the rest of the object graph can be satisfied.
var Cell = cell.Module(
	"agent-infra-endpoints",
	"Cilium Agent infrastructure endpoints",

	cell.Provide(newNoopInfraIPAllocator),
)

func newNoopInfraIPAllocator() InfraIPAllocator {
	return &noopInfraIPAllocator{}
}

// noopInfraIPAllocator is a no-op implementation of InfraIPAllocator for
// non-Linux platforms.
type noopInfraIPAllocator struct{}

var _ InfraIPAllocator = (*noopInfraIPAllocator)(nil)

func (*noopInfraIPAllocator) AllocateIPs(ctx context.Context) error { return nil }

func (*noopInfraIPAllocator) GetHealthEndpointRouting() *linuxrouting.RoutingInfo { return nil }

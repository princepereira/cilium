// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package infraendpoints

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/wait"

	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// InfraIPAllocator is responsible to create infra related IPs (router, ingress
// & health).
type InfraIPAllocator interface {
	AllocateIPs(ctx context.Context) error
	GetHealthEndpointRouting() *linuxrouting.RoutingInfo
}

// Cell initializes the Cilium Agent "infrastructure" endpoints on non-Linux
// platforms. Unlike the Linux cell it does not perform netlink-based device
// setup (there is no cilium_host device managed via netlink here); it only
// allocates the router (cilium_host) internal IP and the service loopback IPs
// from IPAM so that the rest of the object graph and the daemon post-init
// validation are satisfied.
var Cell = cell.Module(
	"agent-infra-endpoints",
	"Cilium Agent infrastructure endpoints",

	cell.Config(config{
		ServiceLoopbackIPv4: "169.254.42.1",
		ServiceLoopbackIPv6: "fe80::1",
	}),
	cell.Provide(newInfraIPAllocator),
)

type config struct {
	ServiceLoopbackIPv4 string `mapstructure:"ipv4-service-loopback-address"`
	ServiceLoopbackIPv6 string `mapstructure:"ipv6-service-loopback-address"`
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.String("ipv4-service-loopback-address", r.ServiceLoopbackIPv4, "IPv4 source address to use for SNAT when a Pod talks to itself over a Service.")
	flags.String("ipv6-service-loopback-address", r.ServiceLoopbackIPv6, "IPv6 source address to use for SNAT when a Pod talks to itself over a Service.")
}

type infraIPAllocatorParams struct {
	cell.In

	Logger         *slog.Logger
	DaemonConfig   *option.DaemonConfig
	Config         config
	NodeAddressing node.Addressing
	LocalNodeStore *node.LocalNodeStore
	IPAM           *ipam.IPAM
}

// infraIPAllocator is a minimal, netlink-free implementation of
// InfraIPAllocator for non-Linux platforms. It allocates the router
// (cilium_host) internal IP and the service loopback IPs from IPAM.
type infraIPAllocator struct {
	logger         *slog.Logger
	daemonConfig   *option.DaemonConfig
	config         config
	nodeAddressing node.Addressing
	localNodeStore *node.LocalNodeStore
	ipam           *ipam.IPAM
}

var _ InfraIPAllocator = (*infraIPAllocator)(nil)

func newInfraIPAllocator(params infraIPAllocatorParams) InfraIPAllocator {
	return &infraIPAllocator{
		logger:         params.Logger,
		daemonConfig:   params.DaemonConfig,
		config:         params.Config,
		nodeAddressing: params.NodeAddressing,
		localNodeStore: params.LocalNodeStore,
		ipam:           params.IPAM,
	}
}

func (r *infraIPAllocator) GetHealthEndpointRouting() *linuxrouting.RoutingInfo {
	// Health endpoint routing is only set up in ENI/Azure IPAM modes on Linux.
	return nil
}

func (r *infraIPAllocator) AllocateIPs(ctx context.Context) error {
	localNode, err := r.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get local node: %w", err)
	}

	if r.daemonConfig.EnableIPv4 {
		routerIP, err := r.allocateRouterIP(ctx, r.nodeAddressing.IPv4(), ipam.IPv4,
			r.daemonConfig.LocalRouterIPv4, localNode.GetCiliumInternalIP(false))
		if err != nil {
			return fmt.Errorf("failed to allocate IPv4 router IP: %w", err)
		}
		r.localNodeStore.Update(func(n *node.LocalNode) { n.SetCiliumInternalIP(routerIP) })
		r.logger.Info("Allocated IPv4 router (cilium_host) address", logfields.IPAddr, routerIP)
	}

	if r.daemonConfig.EnableIPv6 {
		routerIP, err := r.allocateRouterIP(ctx, r.nodeAddressing.IPv6(), ipam.IPv6,
			r.daemonConfig.LocalRouterIPv6, localNode.GetCiliumInternalIP(true))
		if err != nil {
			return fmt.Errorf("failed to allocate IPv6 router IP: %w", err)
		}
		r.localNodeStore.Update(func(n *node.LocalNode) { n.SetCiliumInternalIP(routerIP) })
		r.logger.Info("Allocated IPv6 router (cilium_host) address", logfields.IPAddr, routerIP)
	}

	if err := r.allocateServiceLoopbackIPs(); err != nil {
		return fmt.Errorf("failed to allocate service loopback IPs: %w", err)
	}

	return nil
}

// allocateRouterIP determines the router (cilium_host) internal IP for a single
// address family: an explicitly configured IP, a restored IP from the
// CiliumNode resource, or a freshly allocated IP from the IPAM pool.
func (r *infraIPAllocator) allocateRouterIP(ctx context.Context, family node.AddressingFamily, ipFamily ipam.Family, localRouterIP string, fromK8s net.IP) (net.IP, error) {
	if localRouterIP != "" {
		routerIP := net.ParseIP(localRouterIP)
		if routerIP == nil {
			return nil, fmt.Errorf("invalid local-router-ip: %s", localRouterIP)
		}
		if family.AllocationCIDR().Contains(iputil.AddrFromIP(routerIP)) {
			r.logger.Warn("Specified router IP is within the pod CIDR.")
		}
		return routerIP, nil
	}

	// Avoid allocating the node's external IP as the router IP.
	r.ipam.ExcludeIP(iputil.AddrFromIP(family.PrimaryExternal()), "node-ip", ipam.PoolDefault())

	// Try to restore the previously used router IP from the CiliumNode resource.
	if fromK8s != nil {
		result, err := r.ipam.AllocateIPWithoutSyncUpstream(iputil.AddrFromIP(fromK8s), "router", ipam.PoolDefault())
		if err == nil {
			return net.IP(result.IP.AsSlice()).To16(), nil
		}
		r.logger.Warn("Unable to restore router IP, allocating a fresh one",
			logfields.Error, err,
			logfields.IPAddr, fromK8s,
		)
	}

	result, err := r.allocateNextFromPool(ctx, ipFamily, "router")
	if err != nil {
		return nil, fmt.Errorf("unable to allocate router IP for family %s: %w", ipFamily, err)
	}
	return net.IP(result.IP.AsSlice()).To16(), nil
}

// allocateNextFromPool allocates the next IP from the default IPAM pool,
// retrying with an upstream sync if the pool is not yet provisioned by the
// operator.
func (r *infraIPAllocator) allocateNextFromPool(ctx context.Context, family ipam.Family, owner string) (*ipam.AllocationResult, error) {
	result, err := r.ipam.AllocateNextFamilyWithoutSyncUpstream(family, owner, ipam.PoolDefault())
	if err == nil {
		return result, nil
	}

	var poolErr *ipam.ErrPoolNotReadyYet
	if !errors.As(err, &poolErr) {
		return nil, err
	}

	bo := wait.Backoff{
		Duration: 500 * time.Millisecond,
		Factor:   1.5,
		Jitter:   0.1,
		Steps:    20,
	}

	var lastErr error
	err = wait.ExponentialBackoffWithContext(ctx, bo, func(ctx context.Context) (bool, error) {
		var allocErr error
		result, allocErr = r.ipam.AllocateNextFamily(family, owner, ipam.PoolDefault())
		if allocErr == nil {
			return true, nil
		}

		var poolErr *ipam.ErrPoolNotReadyYet
		if errors.As(allocErr, &poolErr) {
			lastErr = allocErr
			return false, nil
		}

		return true, allocErr
	})

	if err != nil {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, err
	}

	return result, nil
}

func (r *infraIPAllocator) allocateServiceLoopbackIPs() error {
	if r.daemonConfig.EnableIPv6 {
		serviceLoopbackIPv6, err := netip.ParseAddr(r.config.ServiceLoopbackIPv6)
		if err != nil {
			return fmt.Errorf("invalid IPv6 service loopback address: %w", err)
		}
		if !serviceLoopbackIPv6.Is6() {
			return fmt.Errorf("service-loopback-ipv6 must be an IPv6 address, got: %s", r.config.ServiceLoopbackIPv6)
		}
		r.localNodeStore.Update(func(n *node.LocalNode) { n.Local.ServiceLoopbackIPv6 = serviceLoopbackIPv6 })
		r.logger.Debug("Allocated IPv6 service loopback address", logfields.IPAddr, serviceLoopbackIPv6)
	}

	if r.daemonConfig.EnableIPv4 {
		serviceLoopbackIPv4, err := netip.ParseAddr(r.config.ServiceLoopbackIPv4)
		if err != nil {
			return fmt.Errorf("invalid IPv4 service loopback address: %w", err)
		}
		if !serviceLoopbackIPv4.Is4() {
			return fmt.Errorf("service-loopback-ipv4 must be an IPv4 address, got: %s", r.config.ServiceLoopbackIPv4)
		}
		r.localNodeStore.Update(func(n *node.LocalNode) { n.Local.ServiceLoopbackIPv4 = serviceLoopbackIPv4 })
		r.logger.Debug("Allocated IPv4 service loopback address", logfields.IPAddr, serviceLoopbackIPv4)
	}

	return nil
}

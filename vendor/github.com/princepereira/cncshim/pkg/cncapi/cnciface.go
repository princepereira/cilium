// Package cnciface defines the interface and types for the Container Network
// Configuration (CNC) API shim layer.
//
// This package provides a Go-idiomatic interface to the CNC API DLL, which is
// used by Windows container networking (similar to how hcsshim wraps HCS/HNS).
//
// Two implementations are provided:
//   - cncapi: uses windows.LazyDLL (no CGo dependency)
//   - cgoshim: uses CGo to link against cncapi.lib
package cncapi

import "net/netip"

// CNCApi defines the interface for all CNC operations.
// Both syscallshim and cgoshim implement this interface.
type CNCApi interface {
	// Close releases resources and calls CncUninitialize.
	Close() error

	// NodeConfiguration

	GetNodeConfiguration() (*NodeConfigInfo, error)
	AddOrUpdateNodeConfiguration(config *NodeConfigInfo) error
	UpdateNodeConfigurationHashSeeds(seeds *HashSeeds) error
	SetNodeConfigurationInfraInterface(info *NodeInfraNicInfo) error
	GetNodeConfigurationInfraInterface() (*NodeInfraNicInfo, error)

	// Observability

	SetTraceConfiguration(flags NotifyEnableFlags, options *TraceOptions) error
	GetTraceConfiguration() (NotifyEnableFlags, *TraceOptions, error)

	// Connection Tracking

	SetCtConfiguration(config *CTConfigInfo) error
	GetCtConfiguration() (*CTConfigInfo, error)

	// Load Balancer

	CreateLoadBalancerBackends(backends []BackendInfo) error
	CreateLoadBalancerService(serviceID uint16, info *LoadBalancerInfo) error
	UpdateLoadBalancerServiceBackends(serviceID uint16, info *LoadBalancerInfo, newBackends []BackendInfo, oldBackends []BackendInfo) error
	GetLoadBalancerService(frontend *FrontendInfo) (*LoadBalancerInfo, error)
	DeleteLoadBalancerService(serviceID uint16, info *LoadBalancerInfo) error
	DeleteLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) error
	GetLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) ([]BackendQueryResult, error)

	// Endpoint

	AddOrUpdateEndpoint(newEndpoint *EndpointInfo, oldEndpoint *EndpointInfo, disposition CreationDisposition) error
	DeleteEndpoint(address *EndpointAddress) error
	GetEndpoint(address *EndpointAddress) (*EndpointInfo, error)

	// Policy

	GetEndpointPolicy(ifindex uint32, key *PolicyKey) (*Policy, error)
	AddOrUpdateEndpointPolicies(ifindex uint32, policies []Policy) error
	DeleteEndpointPolicies(ifindex uint32, keys []PolicyKey) error

	// Identity

	SetIdentity(subnet netip.Prefix, identity uint32) error
	GetIdentity(subnet netip.Prefix) (uint32, error)
	DeleteIdentity(subnet netip.Prefix) error

	// Neighbor

	AddOrUpdateNeighbor(neighbor *NeighborInfo) error
	DeleteNeighbor(ip netip.Addr) error
	GetNeighbors() ([]NeighborInfo, error)

	// Internet

	AddInternetExcludedSubnets(subnets []netip.Prefix) error
	DeleteInternetExcludedSubnets(subnets []netip.Prefix) error

	// SNAT

	AddSnatExcludedSubnets(subnets []netip.Prefix) error
	DeleteSnatExcludedSubnets(subnets []netip.Prefix) error

	// Garbage Collection

	SetGarbageCollectionConfiguration(config *GarbageCollectionConfig) error

	// Test Configuration

	SetTestConfiguration(config *TestConfigInfo)
	GetTestConfiguration() (*TestConfigInfo, error)
}

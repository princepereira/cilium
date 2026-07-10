package cncapi

import "net/netip"

// MockClient implements CNCApi for testing purposes.
// Each method field can be set to control behavior in tests.
type MockClient struct {
	// Node Configuration
	GetNodeConfigurationFn              func() (*NodeConfigInfo, error)
	AddOrUpdateNodeConfigurationFn      func(config *NodeConfigInfo) error
	UpdateNodeConfigurationHashSeedsFn  func(seeds *HashSeeds) error
	SetNodeConfigurationInfraInterfaceFn func(info *NodeInfraNicInfo) error
	GetNodeConfigurationInfraInterfaceFn func() (*NodeInfraNicInfo, error)

	// Observability
	SetTraceConfigurationFn func(flags NotifyEnableFlags, options *TraceOptions) error
	GetTraceConfigurationFn func() (NotifyEnableFlags, *TraceOptions, error)

	// Connection Tracking
	SetCtConfigurationFn func(config *CTConfigInfo) error
	GetCtConfigurationFn func() (*CTConfigInfo, error)

	// Load Balancer
	CreateLoadBalancerBackendsFn        func(backends []BackendInfo) error
	CreateLoadBalancerServiceFn         func(serviceID uint16, info *LoadBalancerInfo) error
	UpdateLoadBalancerServiceBackendsFn func(serviceID uint16, info *LoadBalancerInfo, newBackends []BackendInfo, oldBackends []BackendInfo) error
	GetLoadBalancerServiceFn            func(frontend *FrontendInfo) (*LoadBalancerInfo, error)
	DeleteLoadBalancerServiceFn         func(serviceID uint16, info *LoadBalancerInfo) error
	DeleteLoadBalancerBackendsFn        func(addressFamily uint16, backendIDs []uint32) error
	GetLoadBalancerBackendsFn           func(addressFamily uint16, backendIDs []uint32) ([]BackendQueryResult, error)

	// Endpoint
	AddOrUpdateEndpointFn func(newEndpoint *EndpointInfo, oldEndpoint *EndpointInfo, disposition CreationDisposition) error
	DeleteEndpointFn      func(address *EndpointAddress) error
	GetEndpointFn         func(address *EndpointAddress) (*EndpointInfo, error)

	// Policy
	GetEndpointPolicyFn            func(ifindex uint32, key *PolicyKey) (*Policy, error)
	AddOrUpdateEndpointPoliciesFn  func(ifindex uint32, policies []Policy) error
	DeleteEndpointPoliciesFn       func(ifindex uint32, keys []PolicyKey) error

	// Identity
	SetIdentityFn    func(subnet netip.Prefix, identity uint32) error
	GetIdentityFn    func(subnet netip.Prefix) (uint32, error)
	DeleteIdentityFn func(subnet netip.Prefix) error

	// Neighbor
	AddOrUpdateNeighborFn func(neighbor *NeighborInfo) error
	DeleteNeighborFn      func(ip netip.Addr) error
	GetNeighborsFn        func() ([]NeighborInfo, error)

	// Internet
	AddInternetExcludedSubnetsFn    func(subnets []netip.Prefix) error
	DeleteInternetExcludedSubnetsFn func(subnets []netip.Prefix) error

	// SNAT
	AddSnatExcludedSubnetsFn    func(subnets []netip.Prefix) error
	DeleteSnatExcludedSubnetsFn func(subnets []netip.Prefix) error

	// Garbage Collection
	SetGarbageCollectionConfigurationFn func(config *GarbageCollectionConfig) error

	// Test Configuration
	SetTestConfigurationFn func(config *TestConfigInfo)
	GetTestConfigurationFn func() (*TestConfigInfo, error)

	// Close
	CloseFn func() error
}

// Verify interface compliance.
var _ CNCApi = (*MockClient)(nil)

func (m *MockClient) Close() error {
	if m.CloseFn != nil {
		return m.CloseFn()
	}
	return nil
}

func (m *MockClient) GetNodeConfiguration() (*NodeConfigInfo, error) {
	if m.GetNodeConfigurationFn != nil {
		return m.GetNodeConfigurationFn()
	}
	return &NodeConfigInfo{}, nil
}

func (m *MockClient) AddOrUpdateNodeConfiguration(config *NodeConfigInfo) error {
	if m.AddOrUpdateNodeConfigurationFn != nil {
		return m.AddOrUpdateNodeConfigurationFn(config)
	}
	return nil
}

func (m *MockClient) UpdateNodeConfigurationHashSeeds(seeds *HashSeeds) error {
	if m.UpdateNodeConfigurationHashSeedsFn != nil {
		return m.UpdateNodeConfigurationHashSeedsFn(seeds)
	}
	return nil
}

func (m *MockClient) SetNodeConfigurationInfraInterface(info *NodeInfraNicInfo) error {
	if m.SetNodeConfigurationInfraInterfaceFn != nil {
		return m.SetNodeConfigurationInfraInterfaceFn(info)
	}
	return nil
}

func (m *MockClient) GetNodeConfigurationInfraInterface() (*NodeInfraNicInfo, error) {
	if m.GetNodeConfigurationInfraInterfaceFn != nil {
		return m.GetNodeConfigurationInfraInterfaceFn()
	}
	return &NodeInfraNicInfo{}, nil
}

func (m *MockClient) SetTraceConfiguration(flags NotifyEnableFlags, options *TraceOptions) error {
	if m.SetTraceConfigurationFn != nil {
		return m.SetTraceConfigurationFn(flags, options)
	}
	return nil
}

func (m *MockClient) GetTraceConfiguration() (NotifyEnableFlags, *TraceOptions, error) {
	if m.GetTraceConfigurationFn != nil {
		return m.GetTraceConfigurationFn()
	}
	return NotifyEnableDefault, &TraceOptions{}, nil
}

func (m *MockClient) SetCtConfiguration(config *CTConfigInfo) error {
	if m.SetCtConfigurationFn != nil {
		return m.SetCtConfigurationFn(config)
	}
	return nil
}

func (m *MockClient) GetCtConfiguration() (*CTConfigInfo, error) {
	if m.GetCtConfigurationFn != nil {
		return m.GetCtConfigurationFn()
	}
	return &CTConfigInfo{}, nil
}

func (m *MockClient) CreateLoadBalancerBackends(backends []BackendInfo) error {
	if m.CreateLoadBalancerBackendsFn != nil {
		return m.CreateLoadBalancerBackendsFn(backends)
	}
	return nil
}

func (m *MockClient) CreateLoadBalancerService(serviceID uint16, info *LoadBalancerInfo) error {
	if m.CreateLoadBalancerServiceFn != nil {
		return m.CreateLoadBalancerServiceFn(serviceID, info)
	}
	return nil
}

func (m *MockClient) UpdateLoadBalancerServiceBackends(serviceID uint16, info *LoadBalancerInfo, newBackends []BackendInfo, oldBackends []BackendInfo) error {
	if m.UpdateLoadBalancerServiceBackendsFn != nil {
		return m.UpdateLoadBalancerServiceBackendsFn(serviceID, info, newBackends, oldBackends)
	}
	return nil
}

func (m *MockClient) GetLoadBalancerService(frontend *FrontendInfo) (*LoadBalancerInfo, error) {
	if m.GetLoadBalancerServiceFn != nil {
		return m.GetLoadBalancerServiceFn(frontend)
	}
	return &LoadBalancerInfo{}, nil
}

func (m *MockClient) DeleteLoadBalancerService(serviceID uint16, info *LoadBalancerInfo) error {
	if m.DeleteLoadBalancerServiceFn != nil {
		return m.DeleteLoadBalancerServiceFn(serviceID, info)
	}
	return nil
}

func (m *MockClient) DeleteLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) error {
	if m.DeleteLoadBalancerBackendsFn != nil {
		return m.DeleteLoadBalancerBackendsFn(addressFamily, backendIDs)
	}
	return nil
}

func (m *MockClient) GetLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) ([]BackendQueryResult, error) {
	if m.GetLoadBalancerBackendsFn != nil {
		return m.GetLoadBalancerBackendsFn(addressFamily, backendIDs)
	}
	return nil, nil
}

func (m *MockClient) AddOrUpdateEndpoint(newEndpoint *EndpointInfo, oldEndpoint *EndpointInfo, disposition CreationDisposition) error {
	if m.AddOrUpdateEndpointFn != nil {
		return m.AddOrUpdateEndpointFn(newEndpoint, oldEndpoint, disposition)
	}
	return nil
}

func (m *MockClient) DeleteEndpoint(address *EndpointAddress) error {
	if m.DeleteEndpointFn != nil {
		return m.DeleteEndpointFn(address)
	}
	return nil
}

func (m *MockClient) GetEndpoint(address *EndpointAddress) (*EndpointInfo, error) {
	if m.GetEndpointFn != nil {
		return m.GetEndpointFn(address)
	}
	return &EndpointInfo{}, nil
}

func (m *MockClient) GetEndpointPolicy(ifindex uint32, key *PolicyKey) (*Policy, error) {
	if m.GetEndpointPolicyFn != nil {
		return m.GetEndpointPolicyFn(ifindex, key)
	}
	return &Policy{}, nil
}

func (m *MockClient) AddOrUpdateEndpointPolicies(ifindex uint32, policies []Policy) error {
	if m.AddOrUpdateEndpointPoliciesFn != nil {
		return m.AddOrUpdateEndpointPoliciesFn(ifindex, policies)
	}
	return nil
}

func (m *MockClient) DeleteEndpointPolicies(ifindex uint32, keys []PolicyKey) error {
	if m.DeleteEndpointPoliciesFn != nil {
		return m.DeleteEndpointPoliciesFn(ifindex, keys)
	}
	return nil
}

func (m *MockClient) SetIdentity(subnet netip.Prefix, identity uint32) error {
	if m.SetIdentityFn != nil {
		return m.SetIdentityFn(subnet, identity)
	}
	return nil
}

func (m *MockClient) GetIdentity(subnet netip.Prefix) (uint32, error) {
	if m.GetIdentityFn != nil {
		return m.GetIdentityFn(subnet)
	}
	return 0, nil
}

func (m *MockClient) DeleteIdentity(subnet netip.Prefix) error {
	if m.DeleteIdentityFn != nil {
		return m.DeleteIdentityFn(subnet)
	}
	return nil
}

func (m *MockClient) AddOrUpdateNeighbor(neighbor *NeighborInfo) error {
	if m.AddOrUpdateNeighborFn != nil {
		return m.AddOrUpdateNeighborFn(neighbor)
	}
	return nil
}

func (m *MockClient) DeleteNeighbor(ip netip.Addr) error {
	if m.DeleteNeighborFn != nil {
		return m.DeleteNeighborFn(ip)
	}
	return nil
}

func (m *MockClient) GetNeighbors() ([]NeighborInfo, error) {
	if m.GetNeighborsFn != nil {
		return m.GetNeighborsFn()
	}
	return nil, nil
}

func (m *MockClient) AddInternetExcludedSubnets(subnets []netip.Prefix) error {
	if m.AddInternetExcludedSubnetsFn != nil {
		return m.AddInternetExcludedSubnetsFn(subnets)
	}
	return nil
}

func (m *MockClient) DeleteInternetExcludedSubnets(subnets []netip.Prefix) error {
	if m.DeleteInternetExcludedSubnetsFn != nil {
		return m.DeleteInternetExcludedSubnetsFn(subnets)
	}
	return nil
}

func (m *MockClient) AddSnatExcludedSubnets(subnets []netip.Prefix) error {
	if m.AddSnatExcludedSubnetsFn != nil {
		return m.AddSnatExcludedSubnetsFn(subnets)
	}
	return nil
}

func (m *MockClient) DeleteSnatExcludedSubnets(subnets []netip.Prefix) error {
	if m.DeleteSnatExcludedSubnetsFn != nil {
		return m.DeleteSnatExcludedSubnetsFn(subnets)
	}
	return nil
}

func (m *MockClient) SetGarbageCollectionConfiguration(config *GarbageCollectionConfig) error {
	if m.SetGarbageCollectionConfigurationFn != nil {
		return m.SetGarbageCollectionConfigurationFn(config)
	}
	return nil
}

func (m *MockClient) SetTestConfiguration(config *TestConfigInfo) {
	if m.SetTestConfigurationFn != nil {
		m.SetTestConfigurationFn(config)
	}
}

func (m *MockClient) GetTestConfiguration() (*TestConfigInfo, error) {
	if m.GetTestConfigurationFn != nil {
		return m.GetTestConfigurationFn()
	}
	return &TestConfigInfo{}, nil
}

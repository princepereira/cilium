package cncapi

// Raw C-compatible struct layouts for the CNC API (cncapi.h).
// These types match the exact memory layout including padding.
// Only valid on Windows amd64.

const (
	abiIPv6AddressLength = 16
	abiMACAddressLength  = 6
	abiAFInet            = 2
	abiAFInet6           = 23
)

// Windows BOOL (32-bit int).
type abiBOOL int32

// Matches cnc_ip_address_t.
type abiIPAddress struct {
	Address       [abiIPv6AddressLength]byte
	AddressFamily uint16
	Pad           uint16
}

// Matches cnc_ip_subnet_t.
type abiIPSubnet struct {
	NetworkAddress abiIPAddress
	Prefix         uint8
	Pad            [3]byte
}

// Matches cnc_mac_address_t.
type abiMACAddress struct {
	Address [abiMACAddressLength]byte
	Pad     uint16
}

// Matches interface_info_t.
type abiInterfaceInfo struct {
	IfIndex    uint32
	MACAddress abiMACAddress
}

// Matches cnc_port_range_t.
type abiPortRange struct {
	MinPort uint16
	MaxPort uint16
}

// Matches cnc_hash_seeds_t.
type abiHashSeeds struct {
	HashSeedIPv4 uint32
	HashSeedIPv6 uint32
}

// Matches cnc_interface_t.
type abiInterface struct {
	IfIndex     uint32
	IPv4Enabled abiBOOL
	IPv6Enabled abiBOOL
	IPv4Address abiIPAddress
	IPv6Address abiIPAddress
}

// Matches cnc_node_config_info_t.
type abiNodeConfigInfo struct {
	NativeInterfacesCount    uintptr
	NativeInterfaces         uintptr // *abiInterfaceInfo
	DirectRoutingInterface   abiInterface
	NodePortServicePortRange abiPortRange
	NodePortNATPortRange     abiPortRange
	HashSeeds                abiHashSeeds
	Pad                      uint32
}

// Matches cnc_node_infra_nic_info_t.
type abiNodeInfraNicInfo struct {
	IfIndex     uint32
	MACAddress  abiMACAddress
	IPv4Enabled abiBOOL
	IPv6Enabled abiBOOL
	IPv4Address abiIPAddress
	IPv6Address abiIPAddress
}

// Matches cnc_trace_options_t.
type abiTraceOptions struct {
	TraceAggregationLevel int32
}

// Matches cnc_ct_config_info_t.
type abiCTConfigInfo struct {
	ConnectionLifetimeTCP    uint32
	ConnectionLifetimeNonTCP uint32
	ServiceLifetimeTCP       uint32
	ServiceLifetimeNonTCP    uint32
	ServiceCloseRebalance    uint32
	SYNTimeout               uint32
	CloseTimeout             uint32
}

// Matches cnc_frontend_info_t.
type abiFrontendInfo struct {
	IPAddress abiIPAddress
	Port      uint16
	Protocol  uint8
	Pad       uint8
}

// Matches cnc_backend_info_t.
type abiBackendInfo struct {
	BackendID uint32
	IPAddress abiIPAddress
	Port      uint16
	Pad       uint16
}

// Matches cnc_backend_query_result_t.
type abiBackendQueryResult struct {
	Info   abiBackendInfo
	Result int32
}

// Matches cnc_load_balancer_info_t.
type abiLoadBalancerInfo struct {
	ServiceType            uint32
	FrontendInfo           abiFrontendInfo
	AffinityTimeoutSeconds uint32
	ServiceFlags           uint32
}

// Matches cnc_endpoint_address_t.
type abiEndpointAddress struct {
	IPv4Enabled abiBOOL
	IPv6Enabled abiBOOL
	IPv4Address abiIPAddress
	IPv6Address abiIPAddress
}

// Matches cnc_endpoint_info_t.
type abiEndpointInfo struct {
	Address    abiEndpointAddress
	MAC        abiMACAddress
	NodeMAC    abiMACAddress
	IfIndex    uint32
	Flags      uint32
	Identity   uint32
	EndpointID uint16
	Pad        uint16
}

// Matches cnc_policy_key_t.
type abiPolicyKey struct {
	Identity        uint32
	Protocol        uint8
	Direction       uint8
	DestinationPort uint16
}

// Matches cnc_policy_value_t.
type abiPolicyValue struct {
	ProxyPort  uint16
	Permission uint8
	Pad        uint8
}

// Matches cnc_policy_t.
type abiPolicy struct {
	Key   abiPolicyKey
	Value abiPolicyValue
}

// Matches cnc_neighbor_info_t.
type abiNeighborInfo struct {
	IPAddress  abiIPAddress
	MACAddress abiMACAddress
}

// Matches cnc_ct_gc_adaptive_config_t.
type abiGCAdaptiveConfig struct {
	StartingTimeIntervalSeconds uint32
	MinTimeIntervalSeconds      uint32
	MaxTimeIntervalSeconds      uint32
}

// Matches cnc_ct_gc_static_config_t.
type abiGCStaticConfig struct {
	TimeIntervalSeconds uint32
}

// Matches cnc_garbage_collection_config_t.
type abiGarbageCollectionConfig struct {
	CTGCMode int32
	Union    [12]byte // union of adaptive (12 bytes) or static (4 bytes)
}

// Matches cnc_test_config_info_t.
type abiTestConfigInfo struct {
	Flags uint32
}

package cncapi

import "net/netip"

// Direction represents traffic direction.
type Direction int

const (
	DirectionIngress Direction = iota
	DirectionEgress
)

// Permission represents a policy permission.
type Permission int

const (
	PermissionAllow Permission = iota
	PermissionDeny
)

// SessionAffinity represents session affinity type.
type SessionAffinity int

const (
	SessionAffinityNone SessionAffinity = iota
	SessionAffinityClientIP
)

// ServiceType represents the Kubernetes service type.
type ServiceType int

const (
	ServiceTypeClusterIP    ServiceType = iota
	ServiceTypeNodePort     ServiceType = iota
	ServiceTypeLoadBalancer ServiceType = iota
	ServiceTypeHostPort     ServiceType = iota
)

// ServiceFlags represents service configuration flags.
type ServiceFlags uint32

const (
	ServiceFlagSessionAffinity             ServiceFlags = 1 << 0
	ServiceFlagInternalTrafficPolicyLocal  ServiceFlags = 1 << 1
	ServiceFlagExternalTrafficPolicyLocal  ServiceFlags = 1 << 2
	ServiceFlagScopeInternal               ServiceFlags = 1 << 3
	ServiceFlagScopeExternal               ServiceFlags = 1 << 4
	ServiceFlagExcludeDefaultNamespace     ServiceFlags = 1 << 5
	ServiceFlagPerPacketLB                 ServiceFlags = 1 << 6
)

// TraceAggregationLevel represents the monitor aggregation level.
type TraceAggregationLevel int

const (
	TraceAggregateUnspecified TraceAggregationLevel = 0
	TraceAggregateNone        TraceAggregationLevel = 1
	TraceAggregateRx          TraceAggregationLevel = 2
	TraceAggregateActiveCT    TraceAggregationLevel = 4
)

// NotifyEnableFlags represents enabled notification events.
type NotifyEnableFlags uint16

const (
	NotifyEnableNone          NotifyEnableFlags = 0
	NotifyEnableDrop          NotifyEnableFlags = 1 << 0
	NotifyEnableTrace         NotifyEnableFlags = 1 << 1
	NotifyEnableDebug         NotifyEnableFlags = 1 << 2
	NotifyEnableDebugCapture  NotifyEnableFlags = 1 << 3
	NotifyEnableTraceSock     NotifyEnableFlags = 1 << 4
	NotifyEnablePolicyVerdict NotifyEnableFlags = 1 << 5
	NotifyEnableUserEvent     NotifyEnableFlags = 1 << 6
	NotifyEnablePktmonDrop    NotifyEnableFlags = 1 << 7
	NotifyEnablePktmonFlow    NotifyEnableFlags = 1 << 8
	NotifyEnableDefault       NotifyEnableFlags = NotifyEnableDrop | NotifyEnableTrace | NotifyEnablePktmonDrop
	NotifyEnableAll           NotifyEnableFlags = 0xFFFF
)

// EndpointFlags represents endpoint flags.
type EndpointFlags uint32

const (
	EndpointFlagNone         EndpointFlags = 0
	EndpointFlagHostEndpoint EndpointFlags = 1 << 0
)

// CreationDisposition specifies behavior on create/update.
type CreationDisposition int32

const (
	CreationDispositionAny     CreationDisposition = iota // Create or update
	CreationDispositionNoExist CreationDisposition = iota // Create only if not exists
	CreationDispositionExist   CreationDisposition = iota // Update only if exists
)

// CTGCMode represents the garbage collection mode.
type CTGCMode int

const (
	CTGCModeAdaptive CTGCMode = 1
	CTGCModeStatic   CTGCMode = 2
)

// TestConfigFlags represents test configuration flags.
type TestConfigFlags uint32

const (
	TestConfigFlagsNone                      TestConfigFlags = 0
	TestConfigFlagsSkipTCProgramAttach       TestConfigFlags = 1 << 0
	TestConfigFlagsSkipNeteventProgramAttach TestConfigFlags = 1 << 1
)

// MACAddress represents a 48-bit MAC address.
type MACAddress [6]byte

// PortRange represents a port range.
type PortRange struct {
	MinPort uint16
	MaxPort uint16
}

// HashSeeds contains hash seeds for IPv4 and IPv6.
type HashSeeds struct {
	IPv4 uint32
	IPv6 uint32
}

// InterfaceInfo represents a network interface.
type InterfaceInfo struct {
	IfIndex    uint32
	MACAddress MACAddress
}

// Interface represents a full interface configuration.
type Interface struct {
	IfIndex     uint32
	IPv4Enabled bool
	IPv6Enabled bool
	IPv4Address netip.Addr
	IPv6Address netip.Addr
}

// NodeConfigInfo represents the node configuration.
type NodeConfigInfo struct {
	NativeInterfaces          []InterfaceInfo
	DirectRoutingInterface    Interface
	NodePortServicePortRange  PortRange
	NodePortNATPortRange      PortRange
	HashSeeds                 HashSeeds
}

// NodeInfraNicInfo represents the infrastructure NIC information.
type NodeInfraNicInfo struct {
	IfIndex     uint32
	MACAddress  MACAddress
	IPv4Enabled bool
	IPv6Enabled bool
	IPv4Address netip.Addr
	IPv6Address netip.Addr
}

// TraceOptions represents trace configuration options.
type TraceOptions struct {
	AggregationLevel TraceAggregationLevel
}

// CTConfigInfo represents connection tracking timeout configuration.
type CTConfigInfo struct {
	ConnectionLifetimeTCP    uint32
	ConnectionLifetimeNonTCP uint32
	ServiceLifetimeTCP       uint32
	ServiceLifetimeNonTCP    uint32
	ServiceCloseRebalance    uint32
	SYNTimeout               uint32
	CloseTimeout             uint32
}

// FrontendInfo represents a load balancer frontend.
type FrontendInfo struct {
	IPAddress netip.Addr
	Port      uint16
	Protocol  uint8
}

// BackendInfo represents a load balancer backend.
type BackendInfo struct {
	BackendID uint32
	IPAddress netip.Addr
	Port      uint16
}

// BackendQueryResult represents the result of a backend query.
type BackendQueryResult struct {
	Info   BackendInfo
	Result HResult
}

// LoadBalancerInfo represents load balancer service configuration.
type LoadBalancerInfo struct {
	ServiceType            ServiceType
	Frontend               FrontendInfo
	AffinityTimeoutSeconds uint32
	ServiceFlags           ServiceFlags
}

// EndpointAddress represents the IP address of an endpoint.
type EndpointAddress struct {
	IPv4Enabled bool
	IPv6Enabled bool
	IPv4Address netip.Addr
	IPv6Address netip.Addr
}

// EndpointInfo represents the endpoint information.
type EndpointInfo struct {
	Address    EndpointAddress
	MAC        MACAddress
	NodeMAC    MACAddress
	IfIndex    uint32
	Flags      EndpointFlags
	Identity   uint32
	EndpointID uint16
}

// PolicyKey represents a policy key.
type PolicyKey struct {
	Identity        uint32
	Protocol        uint8
	Direction       Direction
	DestinationPort uint16
}

// PolicyValue represents a policy value.
type PolicyValue struct {
	ProxyPort  uint16
	Permission Permission
}

// Policy represents a complete policy entry.
type Policy struct {
	Key   PolicyKey
	Value PolicyValue
}

// NeighborInfo represents a neighbor entry.
type NeighborInfo struct {
	IPAddress  netip.Addr
	MACAddress MACAddress
}

// GarbageCollectionAdaptiveConfig is the adaptive GC configuration.
type GarbageCollectionAdaptiveConfig struct {
	StartingTimeIntervalSeconds uint32
	MinTimeIntervalSeconds      uint32
	MaxTimeIntervalSeconds      uint32
}

// GarbageCollectionStaticConfig is the static GC configuration.
type GarbageCollectionStaticConfig struct {
	TimeIntervalSeconds uint32
}

// GarbageCollectionConfig represents garbage collection configuration.
type GarbageCollectionConfig struct {
	Mode     CTGCMode
	Adaptive GarbageCollectionAdaptiveConfig // Used when Mode == CTGCModeAdaptive
	Static   GarbageCollectionStaticConfig   // Used when Mode == CTGCModeStatic
}

// TestConfigInfo represents test configuration.
type TestConfigInfo struct {
	Flags TestConfigFlags
}

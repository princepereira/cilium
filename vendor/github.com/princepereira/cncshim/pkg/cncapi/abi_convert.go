package cncapi

import (
	"encoding/binary"
	"net/netip"
)

// --- Primitive conversions ---

func addrToABI(addr netip.Addr) abiIPAddress {
	var ip abiIPAddress
	if addr.Is4() {
		ip.AddressFamily = abiAFInet
		b := addr.As4()
		binary.LittleEndian.PutUint32(ip.Address[:4], binary.BigEndian.Uint32(b[:]))
	} else if addr.Is6() {
		ip.AddressFamily = abiAFInet6
		b := addr.As16()
		copy(ip.Address[:], b[:])
	}
	return ip
}

func abiToAddr(ip abiIPAddress) netip.Addr {
	switch ip.AddressFamily {
	case abiAFInet:
		var b [4]byte
		v := binary.LittleEndian.Uint32(ip.Address[:4])
		binary.BigEndian.PutUint32(b[:], v)
		return netip.AddrFrom4(b)
	case abiAFInet6:
		var b [16]byte
		copy(b[:], ip.Address[:])
		return netip.AddrFrom16(b)
	default:
		return netip.Addr{}
	}
}

func prefixToABI(prefix netip.Prefix) abiIPSubnet {
	return abiIPSubnet{
		NetworkAddress: addrToABI(prefix.Addr()),
		Prefix:         uint8(prefix.Bits()),
	}
}

func abiToPrefix(subnet abiIPSubnet) netip.Prefix {
	return netip.PrefixFrom(abiToAddr(subnet.NetworkAddress), int(subnet.Prefix))
}

func macToABI(mac MACAddress) abiMACAddress {
	return abiMACAddress{Address: mac}
}

func macFromABI(mac abiMACAddress) MACAddress {
	return mac.Address
}

func boolToABI(b bool) abiBOOL {
	if b {
		return 1
	}
	return 0
}

func boolFromABI(b abiBOOL) bool {
	return b != 0
}

// --- Struct conversions ---

func abiInterfaceInfoToGo(info abiInterfaceInfo) InterfaceInfo {
	return InterfaceInfo{
		IfIndex:    info.IfIndex,
		MACAddress: macFromABI(info.MACAddress),
	}
}

func interfaceInfoToABI(info InterfaceInfo) abiInterfaceInfo {
	return abiInterfaceInfo{
		IfIndex:    info.IfIndex,
		MACAddress: macToABI(info.MACAddress),
	}
}

func abiInterfaceToGo(iface abiInterface) Interface {
	return Interface{
		IfIndex:     iface.IfIndex,
		IPv4Enabled: boolFromABI(iface.IPv4Enabled),
		IPv6Enabled: boolFromABI(iface.IPv6Enabled),
		IPv4Address: abiToAddr(iface.IPv4Address),
		IPv6Address: abiToAddr(iface.IPv6Address),
	}
}

func interfaceToABI(iface Interface) abiInterface {
	return abiInterface{
		IfIndex:     iface.IfIndex,
		IPv4Enabled: boolToABI(iface.IPv4Enabled),
		IPv6Enabled: boolToABI(iface.IPv6Enabled),
		IPv4Address: addrToABI(iface.IPv4Address),
		IPv6Address: addrToABI(iface.IPv6Address),
	}
}

func abiNodeInfraNicInfoToGo(info abiNodeInfraNicInfo) *NodeInfraNicInfo {
	return &NodeInfraNicInfo{
		IfIndex:     info.IfIndex,
		MACAddress:  macFromABI(info.MACAddress),
		IPv4Enabled: boolFromABI(info.IPv4Enabled),
		IPv6Enabled: boolFromABI(info.IPv6Enabled),
		IPv4Address: abiToAddr(info.IPv4Address),
		IPv6Address: abiToAddr(info.IPv6Address),
	}
}

func nodeInfraNicInfoToABI(info *NodeInfraNicInfo) abiNodeInfraNicInfo {
	return abiNodeInfraNicInfo{
		IfIndex:     info.IfIndex,
		MACAddress:  macToABI(info.MACAddress),
		IPv4Enabled: boolToABI(info.IPv4Enabled),
		IPv6Enabled: boolToABI(info.IPv6Enabled),
		IPv4Address: addrToABI(info.IPv4Address),
		IPv6Address: addrToABI(info.IPv6Address),
	}
}

func abiTraceOptionsToGo(opts abiTraceOptions) *TraceOptions {
	return &TraceOptions{
		AggregationLevel: TraceAggregationLevel(opts.TraceAggregationLevel),
	}
}

func traceOptionsToABI(opts *TraceOptions) abiTraceOptions {
	return abiTraceOptions{
		TraceAggregationLevel: int32(opts.AggregationLevel),
	}
}

func abiCTConfigInfoToGo(info abiCTConfigInfo) *CTConfigInfo {
	return &CTConfigInfo{
		ConnectionLifetimeTCP:    info.ConnectionLifetimeTCP,
		ConnectionLifetimeNonTCP: info.ConnectionLifetimeNonTCP,
		ServiceLifetimeTCP:       info.ServiceLifetimeTCP,
		ServiceLifetimeNonTCP:    info.ServiceLifetimeNonTCP,
		ServiceCloseRebalance:    info.ServiceCloseRebalance,
		SYNTimeout:               info.SYNTimeout,
		CloseTimeout:             info.CloseTimeout,
	}
}

func ctConfigInfoToABI(info *CTConfigInfo) abiCTConfigInfo {
	return abiCTConfigInfo{
		ConnectionLifetimeTCP:    info.ConnectionLifetimeTCP,
		ConnectionLifetimeNonTCP: info.ConnectionLifetimeNonTCP,
		ServiceLifetimeTCP:       info.ServiceLifetimeTCP,
		ServiceLifetimeNonTCP:    info.ServiceLifetimeNonTCP,
		ServiceCloseRebalance:    info.ServiceCloseRebalance,
		SYNTimeout:               info.SYNTimeout,
		CloseTimeout:             info.CloseTimeout,
	}
}

func abiFrontendInfoToGo(info abiFrontendInfo) FrontendInfo {
	return FrontendInfo{
		IPAddress: abiToAddr(info.IPAddress),
		Port:      info.Port,
		Protocol:  info.Protocol,
	}
}

func frontendInfoToABI(info *FrontendInfo) abiFrontendInfo {
	return abiFrontendInfo{
		IPAddress: addrToABI(info.IPAddress),
		Port:      info.Port,
		Protocol:  info.Protocol,
	}
}

func abiBackendInfoToGo(info abiBackendInfo) BackendInfo {
	return BackendInfo{
		BackendID: info.BackendID,
		IPAddress: abiToAddr(info.IPAddress),
		Port:      info.Port,
	}
}

func backendInfoToABI(info BackendInfo) abiBackendInfo {
	return abiBackendInfo{
		BackendID: info.BackendID,
		IPAddress: addrToABI(info.IPAddress),
		Port:      info.Port,
	}
}

func abiLoadBalancerInfoToGo(info abiLoadBalancerInfo) *LoadBalancerInfo {
	return &LoadBalancerInfo{
		ServiceType:            ServiceType(info.ServiceType),
		Frontend:               abiFrontendInfoToGo(info.FrontendInfo),
		AffinityTimeoutSeconds: info.AffinityTimeoutSeconds,
		ServiceFlags:           ServiceFlags(info.ServiceFlags),
	}
}

func loadBalancerInfoToABI(info *LoadBalancerInfo) abiLoadBalancerInfo {
	return abiLoadBalancerInfo{
		ServiceType:            uint32(info.ServiceType),
		FrontendInfo:           frontendInfoToABI(&info.Frontend),
		AffinityTimeoutSeconds: info.AffinityTimeoutSeconds,
		ServiceFlags:           uint32(info.ServiceFlags),
	}
}

func abiEndpointAddressToGo(addr abiEndpointAddress) EndpointAddress {
	return EndpointAddress{
		IPv4Enabled: boolFromABI(addr.IPv4Enabled),
		IPv6Enabled: boolFromABI(addr.IPv6Enabled),
		IPv4Address: abiToAddr(addr.IPv4Address),
		IPv6Address: abiToAddr(addr.IPv6Address),
	}
}

func endpointAddressToABI(addr *EndpointAddress) abiEndpointAddress {
	return abiEndpointAddress{
		IPv4Enabled: boolToABI(addr.IPv4Enabled),
		IPv6Enabled: boolToABI(addr.IPv6Enabled),
		IPv4Address: addrToABI(addr.IPv4Address),
		IPv6Address: addrToABI(addr.IPv6Address),
	}
}

func abiEndpointInfoToGo(info abiEndpointInfo) *EndpointInfo {
	return &EndpointInfo{
		Address:    abiEndpointAddressToGo(info.Address),
		MAC:        macFromABI(info.MAC),
		NodeMAC:    macFromABI(info.NodeMAC),
		IfIndex:    info.IfIndex,
		Flags:      EndpointFlags(info.Flags),
		Identity:   info.Identity,
		EndpointID: info.EndpointID,
	}
}

func endpointInfoToABI(info *EndpointInfo) abiEndpointInfo {
	return abiEndpointInfo{
		Address:    endpointAddressToABI(&info.Address),
		MAC:        macToABI(info.MAC),
		NodeMAC:    macToABI(info.NodeMAC),
		IfIndex:    info.IfIndex,
		Flags:      uint32(info.Flags),
		Identity:   info.Identity,
		EndpointID: info.EndpointID,
	}
}

func abiPolicyKeyToGo(key abiPolicyKey) PolicyKey {
	return PolicyKey{
		Identity:        key.Identity,
		Protocol:        key.Protocol,
		Direction:       Direction(key.Direction),
		DestinationPort: key.DestinationPort,
	}
}

func policyKeyToABI(key *PolicyKey) abiPolicyKey {
	return abiPolicyKey{
		Identity:        key.Identity,
		Protocol:        key.Protocol,
		Direction:       uint8(key.Direction),
		DestinationPort: key.DestinationPort,
	}
}

func abiPolicyToGo(p abiPolicy) Policy {
	return Policy{
		Key: abiPolicyKeyToGo(p.Key),
		Value: PolicyValue{
			ProxyPort:  p.Value.ProxyPort,
			Permission: Permission(p.Value.Permission),
		},
	}
}

func policyToABI(p Policy) abiPolicy {
	return abiPolicy{
		Key: policyKeyToABI(&p.Key),
		Value: abiPolicyValue{
			ProxyPort:  p.Value.ProxyPort,
			Permission: uint8(p.Value.Permission),
		},
	}
}

func abiNeighborInfoToGo(info abiNeighborInfo) NeighborInfo {
	return NeighborInfo{
		IPAddress:  abiToAddr(info.IPAddress),
		MACAddress: macFromABI(info.MACAddress),
	}
}

func neighborInfoToABI(info *NeighborInfo) abiNeighborInfo {
	return abiNeighborInfo{
		IPAddress:  addrToABI(info.IPAddress),
		MACAddress: macToABI(info.MACAddress),
	}
}

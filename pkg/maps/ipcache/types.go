// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000

	// Name is the canonical name for the IPCache map on the filesystem.
	Name = "cilium_ipcache_v2"
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct ipcache_key in <bpf/lib/eps.h>
type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	ClusterID uint16 `align:"cluster_id"`
	Pad1      uint8  `align:"pad1"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

const staticPrefixBits = uint32(unsafe.Sizeof(Key{})-
	unsafe.Sizeof(Key{}.Prefixlen)-
	unsafe.Sizeof(Key{}.IP)) * 8

func (k Key) String() string {
	var addr netip.Addr

	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr = netip.AddrFrom4([4]byte(k.IP[:4]))
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	default:
		return "<unknown>"
	}

	prefixLen := int(k.Prefixlen - staticPrefixBits)
	clusterID := uint32(k.ClusterID)

	return cmtypes.PrefixClusterFrom(netip.PrefixFrom(addr, prefixLen), cmtypes.WithClusterID(clusterID)).String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

func (k Key) Prefix() netip.Prefix {
	var addr netip.Addr
	prefixLen := int(k.Prefixlen - staticPrefixBits)
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr = netip.AddrFrom4([4]byte(k.IP[:4]))
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	}
	return netip.PrefixFrom(addr, prefixLen)
}

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF ipcache.
func getPrefixLen(prefixBits int) uint32 {
	return staticPrefixBits + uint32(prefixBits)
}

// NewKey returns a Key based on the prefix and cluster ID.
// The address family is automatically detected
func NewKey(prefix netip.Prefix, clusterID uint16) Key {
	result := Key{
		Prefixlen: getPrefixLen(prefix.Bits()),
		ClusterID: clusterID,
	}

	addr := prefix.Addr()
	copy(result.IP[:], addr.AsSlice())
	if addr.Is4() {
		result.Family = bpf.EndpointKeyIPv4
	} else if addr.Is6() {
		result.Family = bpf.EndpointKeyIPv6
	}

	return result
}

// RemoteEndpointInfoFlags represents various flags that can be attached to
// remote endpoints in the IPCache.
type RemoteEndpointInfoFlags uint8

// String returns a human-readable representation of the flags present in the
// RemoteEndpointInfoFlags.
func (f RemoteEndpointInfoFlags) String() string {
	flags := ""
	if f&FlagSkipTunnel != 0 {
		flags += "skiptunnel,"
	}
	if f&FlagHasTunnelEndpoint != 0 {
		flags += "hastunnel,"
	}
	if f&FlagIPv6TunnelEndpoint != 0 {
		flags += "ipv6tunnel,"
	}
	if f&FlagRemoteCluster != 0 {
		flags += "remotecluster,"
	}

	if flags == "" {
		return "<none>"
	}
	return strings.TrimSuffix(flags, ",")
}

const (
	FlagSkipTunnel          RemoteEndpointInfoFlags = 1 << iota
	FlagHasTunnelEndpoint
	FlagIPv6TunnelEndpoint
	FlagRemoteCluster
)

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
type RemoteEndpointInfo struct {
	SecurityIdentity uint32 `align:"sec_identity"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	TunnelEndpoint types.IPv6 `align:"tunnel_endpoint"`
	_              uint16
	Key            uint8                   `align:"key"`
	Flags          RemoteEndpointInfoFlags `align:"flag_skip_tunnel"`
}

func (v *RemoteEndpointInfo) String() string {
	return fmt.Sprintf("identity=%d encryptkey=%d tunnelendpoint=%s flags=%s",
		v.SecurityIdentity, v.Key, v.GetTunnelEndpoint(), v.Flags)
}

func (v *RemoteEndpointInfo) GetTunnelEndpoint() netip.Addr {
	if v.Flags&FlagIPv6TunnelEndpoint == 0 {
		return netip.AddrFrom4([4]byte(v.TunnelEndpoint[:4]))
	}
	return netip.AddrFrom16(v.TunnelEndpoint)
}

func (v *RemoteEndpointInfo) New() bpf.MapValue { return &RemoteEndpointInfo{} }

// NewValue returns a RemoteEndpointInfo based on the provided security
// identity, tunnel endpoint IP, IPsec key, and flags.
func NewValue(secID uint32, tunnelEndpoint netip.Addr, key uint8, flags RemoteEndpointInfoFlags) RemoteEndpointInfo {
	result := RemoteEndpointInfo{
		SecurityIdentity: secID,
		Key:              key,
		Flags:            flags,
	}

	if !tunnelEndpoint.IsValid() {
		return result
	}

	result.Flags |= FlagHasTunnelEndpoint
	copy(result.TunnelEndpoint[:], tunnelEndpoint.AsSlice())
	if tunnelEndpoint.Is6() {
		result.Flags |= FlagIPv6TunnelEndpoint
	}

	return result
}

// Map represents an IPCache BPF map.
type Map struct {
	bpf.Map
}

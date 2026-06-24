// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package srv6map

import (
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

var Cell = cell.Module(
	"srv6map",
	"SRv6 Maps",
)

const policyStaticPrefixBits = 32

// PolicyKey4 is a key for the PolicyMap4. Implements bpf.MapKey.
type PolicyKey4 struct {
	PrefixLen uint32     `align:"lpm"`
	VRFID     uint32     `align:"vrf_id"`
	DestCIDR  types.IPv4 `align:"dst_cidr"`
}

func (k *PolicyKey4) New() bpf.MapKey { return &PolicyKey4{} }
func (k *PolicyKey4) String() string {
	return fmt.Sprintf("vrfid=%d, destCIDR=%s", k.VRFID, k.getDestCIDR())
}
func (k *PolicyKey4) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(k.DestCIDR.Addr(), int(k.PrefixLen-policyStaticPrefixBits))
}

// PolicyKey6 is a key for the PolicyMap6. Implements bpf.MapKey.
type PolicyKey6 struct {
	PrefixLen uint32     `align:"lpm"`
	VRFID     uint32     `align:"vrf_id"`
	DestCIDR  types.IPv6 `align:"dst_cidr"`
}

func (k *PolicyKey6) New() bpf.MapKey { return &PolicyKey6{} }
func (k *PolicyKey6) String() string {
	return fmt.Sprintf("vrfid=%d, destCIDR=%s", k.VRFID, k.getDestCIDR())
}
func (k *PolicyKey6) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(k.DestCIDR.Addr(), int(k.PrefixLen-policyStaticPrefixBits))
}

// PolicyKey abstracts away the differences between PolicyKey4 and PolicyKey6.
type PolicyKey struct {
	VRFID    uint32
	DestCIDR netip.Prefix
}

// PolicyValue is a value for the PolicyMap4/6. Implements bpf.MapValue.
type PolicyValue struct {
	SID types.IPv6
}

func (v *PolicyValue) New() bpf.MapValue { return &PolicyValue{} }
func (v *PolicyValue) String() string    { return fmt.Sprintf("sid=%s", v.SID.String()) }

type SRv6PolicyIterateCallback func(*PolicyKey, *PolicyValue)

type PolicyMap4 struct{}
type PolicyMap6 struct{}

func (*PolicyMap4) IterateWithCallback(SRv6PolicyIterateCallback) error { return nil }
func (*PolicyMap6) IterateWithCallback(SRv6PolicyIterateCallback) error { return nil }

// VRFKey4 is a key for the VRFMap4. Implements bpf.MapKey.
type VRFKey4 struct {
	PrefixLen uint32     `align:"lpm"`
	SourceIP  types.IPv4 `align:"src_ip"`
	DestCIDR  types.IPv4 `align:"dst_cidr"`
}

func (v *VRFKey4) New() bpf.MapKey { return &VRFKey4{} }
func (v *VRFKey4) String() string {
	return fmt.Sprintf("srcip=%s, destCIDR=%s", v.SourceIP, v.getDestCIDR())
}
func (k *VRFKey4) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(k.DestCIDR.Addr(), int(k.PrefixLen-32))
}

// VRFKey6 is a key for the VRFMap6. Implements bpf.MapKey.
type VRFKey6 struct {
	PrefixLen uint32     `align:"lpm"`
	SourceIP  types.IPv6 `align:"src_ip"`
	DestCIDR  types.IPv6 `align:"dst_cidr"`
}

func (v *VRFKey6) New() bpf.MapKey { return &VRFKey6{} }
func (v *VRFKey6) String() string {
	return fmt.Sprintf("srcip=%s, destCIDR=%s", v.SourceIP, v.getDestCIDR())
}
func (k *VRFKey6) getDestCIDR() netip.Prefix {
	return netip.PrefixFrom(k.DestCIDR.Addr(), int(k.PrefixLen-128))
}

// VRFKey abstracts away the differences between VRFKey4 and VRFKey6.
type VRFKey struct {
	SourceIP netip.Addr
	DestCIDR netip.Prefix
}

// VRFValue is a value for the VRFMap4/6. Implements bpf.MapValue.
type VRFValue struct {
	ID uint32
}

func (v *VRFValue) New() bpf.MapValue { return &VRFValue{} }
func (v *VRFValue) String() string    { return fmt.Sprintf("vrfid=%d", v.ID) }

type SRv6VRFIterateCallback func(*VRFKey, *VRFValue)

type VRFMap4 struct{}
type VRFMap6 struct{}

func (*VRFMap4) IterateWithCallback(SRv6VRFIterateCallback) error { return nil }
func (*VRFMap6) IterateWithCallback(SRv6VRFIterateCallback) error { return nil }

// SIDKey is a key for the SIDMap. Implements bpf.MapKey.
type SIDKey struct {
	SID types.IPv6
}

func (k *SIDKey) New() bpf.MapKey { return &SIDKey{} }
func (k *SIDKey) String() string  { return fmt.Sprintf("sid=%s", k.SID.String()) }

// SIDValue is a value for the SIDMap. Implements bpf.MapValue.
type SIDValue struct {
	VRFID uint32
}

func (v *SIDValue) New() bpf.MapValue { return &SIDValue{} }
func (v *SIDValue) String() string    { return fmt.Sprintf("vrfid=%d", v.VRFID) }

type SRv6SIDIterateCallback func(*SIDKey, *SIDValue)

type SIDMap struct{}

func (*SIDMap) IterateWithCallback(SRv6SIDIterateCallback) error { return nil }

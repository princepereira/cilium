// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package egressmap

import (
	"fmt"
	"log/slog"
	"net/netip"
	"unsafe"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/types"
)

const (
	PolicyMapName4   = "cilium_egress_gw_policy_v4"
	PolicyMapName4V2 = "cilium_egress_gw_policy_v4_v2"
	PolicyMapName6   = "cilium_egress_gw_policy_v6"

	PolicyStaticPrefixBits4 = uint32(unsafe.Sizeof(types.IPv4{}) * 8)
	PolicyStaticPrefixBits6 = uint32(unsafe.Sizeof(types.IPv6{}) * 8)
)

var Cell = cell.Module(
	"egressmaps",
	"Egressmaps provide access to the egress gateway datapath maps",
	cell.Config(DefaultPolicyConfig),
)

// EgressPolicyKey4 is the key of an egress policy map.
type EgressPolicyKey4 struct {
	PrefixLen uint32     `align:"lpm_key"`
	SourceIP  types.IPv4 `align:"saddr"`
	DestCIDR  types.IPv4 `align:"daddr"`
}

// EgressPolicyVal4 is the value of an egress policy map.
type EgressPolicyVal4 struct {
	EgressIP  types.IPv4 `align:"egress_ip"`
	GatewayIP types.IPv4 `align:"gateway_ip"`
}

type EgressPolicyVal4V2 struct {
	EgressIP      types.IPv4 `align:"egress_ip"`
	GatewayIP     types.IPv4 `align:"gateway_ip"`
	Reserved      [3]uint32  `align:"reserved"`
	EgressIfindex uint32     `align:"egress_ifindex"`
	Reserved2     uint32     `align:"reserved2"`
}

// EgressPolicyKey6 is the key of an egress policy map.
type EgressPolicyKey6 struct {
	PrefixLen uint32     `align:"lpm_key"`
	SourceIP  types.IPv6 `align:"saddr"`
	DestCIDR  types.IPv6 `align:"daddr"`
}

// EgressPolicyVal6 is the value of an egress policy map.
type EgressPolicyVal6 struct {
	EgressIP      types.IPv6 `align:"egress_ip"`
	GatewayIP     types.IPv4 `align:"gateway_ip"`
	Reserved      [3]uint32  `align:"reserved"`
	EgressIfindex uint32     `align:"egress_ifindex"`
	Reserved2     uint32     `align:"reserved2"`
}

type PolicyConfig struct {
	EgressGatewayPolicyMapMax int
}

var DefaultPolicyConfig = PolicyConfig{
	EgressGatewayPolicyMapMax: 1 << 14,
}

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int("egress-gateway-policy-map-max", def.EgressGatewayPolicyMapMax, "Maximum number of entries in egress gateway policy map")
}

type PolicyMap4 struct {
	entries map[EgressPolicyKey4]EgressPolicyVal4
}

type PolicyMap4V2 struct {
	entries map[EgressPolicyKey4]EgressPolicyVal4V2
}

type PolicyMap6 struct {
	entries map[EgressPolicyKey6]EgressPolicyVal6
}

func NewEgressPolicyKey4(sourceIP netip.Addr, destPrefix netip.Prefix) EgressPolicyKey4 {
	key := EgressPolicyKey4{}
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destPrefix.Addr())
	key.PrefixLen = PolicyStaticPrefixBits4 + uint32(destPrefix.Bits())
	return key
}

func NewEgressPolicyVal4(egressIP, gatewayIP netip.Addr) EgressPolicyVal4 {
	val := EgressPolicyVal4{}
	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP.FromAddr(gatewayIP)
	return val
}

func NewEgressPolicyVal4V2(egressIP, gatewayIP netip.Addr, egressIfindex uint32) EgressPolicyVal4V2 {
	val := EgressPolicyVal4V2{}
	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP.FromAddr(gatewayIP)
	val.EgressIfindex = egressIfindex
	return val
}

func (k *EgressPolicyKey4) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-PolicyStaticPrefixBits4)
}
func (k *EgressPolicyKey4) New() bpf.MapKey { return &EgressPolicyKey4{} }
func (k *EgressPolicyKey4) Match(sourceIP netip.Addr, destCIDR netip.Prefix) bool {
	return k.GetSourceIP() == sourceIP && k.GetDestCIDR() == destCIDR
}
func (k *EgressPolicyKey4) GetSourceIP() netip.Addr { return k.SourceIP.Addr() }
func (k *EgressPolicyKey4) GetDestCIDR() netip.Prefix {
	return netip.PrefixFrom(k.DestCIDR.Addr(), int(k.PrefixLen-PolicyStaticPrefixBits4))
}

func (v *EgressPolicyVal4) New() bpf.MapValue   { return &EgressPolicyVal4{} }
func (v *EgressPolicyVal4V2) New() bpf.MapValue { return &EgressPolicyVal4V2{} }
func (v *EgressPolicyVal4) Match(egressIP, gatewayIP netip.Addr) bool {
	return v.GetEgressAddr() == egressIP && v.GetGatewayAddr() == gatewayIP
}
func (v *EgressPolicyVal4V2) Match(egressIP, gatewayIP netip.Addr, egressIfindex uint32) bool {
	return v.GetEgressAddr() == egressIP && v.GetGatewayAddr() == gatewayIP && v.EgressIfindex == egressIfindex
}
func (v *EgressPolicyVal4) GetEgressAddr() netip.Addr    { return v.EgressIP.Addr() }
func (v *EgressPolicyVal4V2) GetEgressAddr() netip.Addr  { return v.EgressIP.Addr() }
func (v *EgressPolicyVal4) GetGatewayAddr() netip.Addr   { return v.GatewayIP.Addr() }
func (v *EgressPolicyVal4V2) GetGatewayAddr() netip.Addr { return v.GatewayIP.Addr() }
func (v *EgressPolicyVal4) String() string {
	return fmt.Sprintf("%s %s", v.GetGatewayAddr(), v.GetEgressAddr())
}
func (v *EgressPolicyVal4V2) String() string {
	return fmt.Sprintf("%s %s %d", v.GetGatewayAddr(), v.GetEgressAddr(), v.EgressIfindex)
}

func NewEgressPolicyKey6(sourceIP netip.Addr, destPrefix netip.Prefix) EgressPolicyKey6 {
	key := EgressPolicyKey6{}
	key.SourceIP.FromAddr(sourceIP)
	key.DestCIDR.FromAddr(destPrefix.Addr())
	key.PrefixLen = PolicyStaticPrefixBits6 + uint32(destPrefix.Bits())
	return key
}

func NewEgressPolicyVal6(egressIP, gatewayIP netip.Addr, egressIfindex uint32) EgressPolicyVal6 {
	val := EgressPolicyVal6{}
	val.EgressIP.FromAddr(egressIP)
	val.GatewayIP.FromAddr(gatewayIP)
	val.EgressIfindex = egressIfindex
	return val
}

func (k *EgressPolicyKey6) String() string {
	return fmt.Sprintf("%s %s/%d", k.SourceIP, k.DestCIDR, k.PrefixLen-PolicyStaticPrefixBits6)
}
func (k *EgressPolicyKey6) New() bpf.MapKey { return &EgressPolicyKey6{} }
func (k *EgressPolicyKey6) Match(sourceIP netip.Addr, destCIDR netip.Prefix) bool {
	return k.GetSourceIP() == sourceIP && k.GetDestCIDR() == destCIDR
}
func (k *EgressPolicyKey6) GetSourceIP() netip.Addr { return k.SourceIP.Addr() }
func (k *EgressPolicyKey6) GetDestCIDR() netip.Prefix {
	return netip.PrefixFrom(k.DestCIDR.Addr(), int(k.PrefixLen-PolicyStaticPrefixBits6))
}

func (v *EgressPolicyVal6) New() bpf.MapValue { return &EgressPolicyVal6{} }
func (v *EgressPolicyVal6) Match(egressIP, gatewayIP netip.Addr, egressIfindex uint32) bool {
	return v.GetEgressAddr() == egressIP && v.GetGatewayAddr() == gatewayIP && v.EgressIfindex == egressIfindex
}
func (v *EgressPolicyVal6) GetEgressAddr() netip.Addr  { return v.EgressIP.Addr() }
func (v *EgressPolicyVal6) GetGatewayAddr() netip.Addr { return v.GatewayIP.Addr() }
func (v *EgressPolicyVal6) String() string {
	return fmt.Sprintf("%s %s %d", v.GetGatewayAddr(), v.GetEgressAddr(), v.EgressIfindex)
}

func CreatePrivatePolicyMap4(cell.Lifecycle, *metrics.Registry, PolicyConfig) *PolicyMap4 {
	return &PolicyMap4{entries: map[EgressPolicyKey4]EgressPolicyVal4{}}
}

func CreatePrivatePolicyMap4V2(cell.Lifecycle, *metrics.Registry, PolicyConfig) *PolicyMap4V2 {
	return &PolicyMap4V2{entries: map[EgressPolicyKey4]EgressPolicyVal4V2{}}
}

func CreatePrivatePolicyMap6(cell.Lifecycle, *metrics.Registry, PolicyConfig) *PolicyMap6 {
	return &PolicyMap6{entries: map[EgressPolicyKey6]EgressPolicyVal6{}}
}

func OpenPinnedPolicyMap4(*slog.Logger) (*PolicyMap4, error) {
	return CreatePrivatePolicyMap4(nil, nil, DefaultPolicyConfig), nil
}
func OpenPinnedPolicyMap4V2(*slog.Logger) (*PolicyMap4V2, error) {
	return CreatePrivatePolicyMap4V2(nil, nil, DefaultPolicyConfig), nil
}
func OpenPinnedPolicyMap6(*slog.Logger) (*PolicyMap6, error) {
	return CreatePrivatePolicyMap6(nil, nil, DefaultPolicyConfig), nil
}

type EgressPolicyIterateCallback func(*EgressPolicyKey4, *EgressPolicyVal4)
type EgressPolicyIterateCallbackV2 func(*EgressPolicyKey4, *EgressPolicyVal4V2)
type EgressPolicyIterateCallback6 func(*EgressPolicyKey6, *EgressPolicyVal6)

func (m *PolicyMap4) ensureEntries() {
	if m.entries == nil {
		m.entries = map[EgressPolicyKey4]EgressPolicyVal4{}
	}
}

func (m *PolicyMap4V2) ensureEntries() {
	if m.entries == nil {
		m.entries = map[EgressPolicyKey4]EgressPolicyVal4V2{}
	}
}

func (m *PolicyMap6) ensureEntries() {
	if m.entries == nil {
		m.entries = map[EgressPolicyKey6]EgressPolicyVal6{}
	}
}

func (m *PolicyMap4) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4, error) {
	if m == nil {
		return nil, nil
	}
	val, ok := m.entries[NewEgressPolicyKey4(sourceIP, destCIDR)]
	if !ok {
		return nil, nil
	}
	return &val, nil
}

func (m *PolicyMap4V2) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal4V2, error) {
	if m == nil {
		return nil, nil
	}
	val, ok := m.entries[NewEgressPolicyKey4(sourceIP, destCIDR)]
	if !ok {
		return nil, nil
	}
	return &val, nil
}

func (m *PolicyMap6) Lookup(sourceIP netip.Addr, destCIDR netip.Prefix) (*EgressPolicyVal6, error) {
	if m == nil {
		return nil, nil
	}
	val, ok := m.entries[NewEgressPolicyKey6(sourceIP, destCIDR)]
	if !ok {
		return nil, nil
	}
	return &val, nil
}

func (m *PolicyMap4) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr) error {
	m.ensureEntries()
	m.entries[NewEgressPolicyKey4(sourceIP, destCIDR)] = NewEgressPolicyVal4(egressIP, gatewayIP)
	return nil
}

func (m *PolicyMap4V2) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr, egressIfindex uint32) error {
	m.ensureEntries()
	m.entries[NewEgressPolicyKey4(sourceIP, destCIDR)] = NewEgressPolicyVal4V2(egressIP, gatewayIP, egressIfindex)
	return nil
}

func (m *PolicyMap6) Update(sourceIP netip.Addr, destCIDR netip.Prefix, egressIP, gatewayIP netip.Addr, egressIfindex uint32) error {
	m.ensureEntries()
	m.entries[NewEgressPolicyKey6(sourceIP, destCIDR)] = NewEgressPolicyVal6(egressIP, gatewayIP, egressIfindex)
	return nil
}

func (m *PolicyMap4) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	if m != nil {
		delete(m.entries, NewEgressPolicyKey4(sourceIP, destCIDR))
	}
	return nil
}

func (m *PolicyMap4V2) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	if m != nil {
		delete(m.entries, NewEgressPolicyKey4(sourceIP, destCIDR))
	}
	return nil
}

func (m *PolicyMap6) Delete(sourceIP netip.Addr, destCIDR netip.Prefix) error {
	if m != nil {
		delete(m.entries, NewEgressPolicyKey6(sourceIP, destCIDR))
	}
	return nil
}

func (m *PolicyMap4) IterateWithCallback(cb EgressPolicyIterateCallback) error {
	for key, value := range m.entries {
		k, v := key, value
		cb(&k, &v)
	}
	return nil
}

func (m *PolicyMap4V2) IterateWithCallback(cb EgressPolicyIterateCallbackV2) error {
	for key, value := range m.entries {
		k, v := key, value
		cb(&k, &v)
	}
	return nil
}

func (m *PolicyMap6) IterateWithCallback(cb EgressPolicyIterateCallback6) error {
	for key, value := range m.entries {
		k, v := key, value
		cb(&k, &v)
	}
	return nil
}

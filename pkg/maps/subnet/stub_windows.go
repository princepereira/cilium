// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package subnet

import (
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const MapName = "cilium_subnet_map"

type SubnetMapKey struct {
	Prefixlen uint32
	Family    uint8
	IP        types.IPv6
}

func getStaticPrefixBits() uint32 { return 0 }
func (k *SubnetMapKey) New() bpf.MapKey { return &SubnetMapKey{} }
func (k SubnetMapKey) Prefix() netip.Prefix { return netip.Prefix{} }
func (k SubnetMapKey) String() string { return "" }

type SubnetMapValue struct {
	Identity uint32
}

func (v *SubnetMapValue) String() string    { return fmt.Sprintf("identity=%d", v.Identity) }
func (v *SubnetMapValue) New() bpf.MapValue { return &SubnetMapValue{} }
func NewValue(identity uint32) SubnetMapValue { return SubnetMapValue{Identity: identity} }

type subnetMap struct { *bpf.Map }

func SubnetMap() *bpf.Map { return &bpf.Map{} }
func newSubnetMap(*option.DaemonConfig, cell.Lifecycle) bpf.MapOut[subnetMap] {
	return bpf.NewMapOut(subnetMap{Map: SubnetMap()})
}

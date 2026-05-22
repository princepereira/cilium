// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ipmasq

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/metrics"
)

const (
	MapNameIPv4 = "cilium_ipmasq_v4"
	MapNameIPv6 = "cilium_ipmasq_v6"
)

type IPMasqBPFMap struct {
	MetricsRegistry *metrics.Registry
}

func IPMasq4Map(*metrics.Registry) *bpf.Map { return &bpf.Map{} }
func IPMasq6Map(*metrics.Registry) *bpf.Map { return &bpf.Map{} }
func (m *IPMasqBPFMap) Update(netip.Prefix) error { return nil }
func (m *IPMasqBPFMap) Delete(netip.Prefix) error { return nil }
func (m *IPMasqBPFMap) DumpForProtocols(bool, bool) ([]netip.Prefix, error) { return nil, nil }
func (m *IPMasqBPFMap) Dump() ([]netip.Prefix, error) { return nil, nil }

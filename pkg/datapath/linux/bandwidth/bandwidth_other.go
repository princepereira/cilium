// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package bandwidth

import (
	"time"

	"github.com/cilium/hive/cell"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	EgressBandwidth  = "kubernetes.io/egress-bandwidth"
	IngressBandwidth = "kubernetes.io/ingress-bandwidth"
	Priority         = "bandwidth.cilium.io/priority"

	FqDefaultHorizon = 2 * time.Second
	FqDefaultBuckets = 15

	GuaranteedQoSDefaultPriority = 6 + 1
	BurstableQoSDefaultPriority  = 8 + 1
	BestEffortQoSDefaultPriority = 5 + 1

	DirectionEgress  uint8 = 0
	DirectionIngress uint8 = 1
)

var Cell = cell.Module(
	"bandwidth-manager",
	"Linux Bandwidth Manager for EDT-based pacing",
	cell.Provide(func() Manager { return manager{} }),
)

type Manager interface {
	BBREnabled() bool
	Enabled() bool

	UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32)
	DeleteBandwidthLimit(endpointID uint16)

	UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64)
	DeleteIngressBandwidthLimit(endpointID uint16)
}

type manager struct{}

func (manager) BBREnabled() bool { return false }
func (manager) Enabled() bool    { return false }

func (manager) UpdateBandwidthLimit(uint16, uint64, uint32) {}
func (manager) DeleteBandwidthLimit(uint16)                 {}

func (manager) UpdateIngressBandwidthLimit(uint16, uint64) {}
func (manager) DeleteIngressBandwidthLimit(uint16)         {}

func GetBytesPerSec(bandwidth string) (uint64, error) {
	res, err := resource.ParseQuantity(bandwidth)
	if err != nil {
		return 0, err
	}
	return uint64(res.Value() / 8), err
}

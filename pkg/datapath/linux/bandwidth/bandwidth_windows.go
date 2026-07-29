// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

// This is the non-Linux variant of the bandwidth manager. The real
// implementation depends on the BPF bandwidth map and Linux qdisc/netlink
// facilities which have no equivalent on other platforms. Here we provide a
// disabled, no-op Manager so that the cross-platform packages consuming
// bandwidth.Manager (endpoint, endpointmanager, ...) can be built and run.

package bandwidth

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth/types"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
)

const (
	// EgressBandwidth is the K8s Pod annotation.
	EgressBandwidth = "kubernetes.io/egress-bandwidth"
	// IngressBandwidth is the K8s Pod annotation.
	IngressBandwidth = "kubernetes.io/ingress-bandwidth"
	// Priority is the Cilium Pod priority annotation.
	Priority = "bandwidth.cilium.io/priority"

	// GuaranteedQoSDefaultPriority prio value to classify packets to high prio band
	GuaranteedQoSDefaultPriority = 6 + 1
	// BurstableQoSDefaultPriority prio value to classify packets to medium prio band
	BurstableQoSDefaultPriority = 8 + 1
	// BestEffortQoSDefaultPriority prio value to classify packets to medium prio band
	BestEffortQoSDefaultPriority = 5 + 1
)

// Manager is the bandwidth manager interface. Mirrors the Linux definition.
type Manager interface {
	BBREnabled() bool
	Enabled() bool

	UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32)
	DeleteBandwidthLimit(endpointID uint16)

	UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64)
	DeleteIngressBandwidthLimit(endpointID uint16)
}

// GetBytesPerSec parses a K8s bandwidth annotation into bytes per second.
func GetBytesPerSec(bandwidth string) (uint64, error) {
	res, err := resource.ParseQuantity(bandwidth)
	if err != nil {
		return 0, err
	}
	return uint64(res.Value() / 8), err
}

// disabledManager is a no-op Manager used on non-Linux platforms.
type disabledManager struct{}

func (*disabledManager) BBREnabled() bool { return false }
func (*disabledManager) Enabled() bool    { return false }

func (*disabledManager) UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32) {
}
func (*disabledManager) DeleteBandwidthLimit(endpointID uint16)                             {}
func (*disabledManager) UpdateIngressBandwidthLimit(endpointID uint16, bytesPerSecond uint64) {}
func (*disabledManager) DeleteIngressBandwidthLimit(endpointID uint16)                      {}

var defaultConfig = types.Config{
	EnableBandwidthManager: false,
	EnableBBR:              false,
	EnableBBRHostnsOnly:    false,
}

// Cell provides a disabled bandwidth Manager on non-Linux platforms.
var Cell = cell.Module(
	"bandwidth-manager",
	"Bandwidth Manager for EDT-based pacing - disabled on this platform",

	cell.Config(defaultConfig),
	cell.Provide(newBandwidthManager),
)

func newBandwidthManager(logger *slog.Logger) (Manager, defines.NodeFnOut) {
	return &disabledManager{}, defines.NewNodeFnOut(func() (defines.Map, error) {
		return defines.Map{}, nil
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipsec

import (
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/node"
)

// disabledAgent is a no-op [types.Agent] used on non-Linux platforms, where the
// XFRM-based IPsec datapath is unavailable.
type disabledAgent struct{}

func (disabledAgent) Enabled() bool    { return false }
func (disabledAgent) AuthKeySize() int { return 0 }
func (disabledAgent) StartBackgroundJobs(node.Handler, <-chan struct{}) error {
	return nil
}
func (disabledAgent) UpsertIPsecEndpoint(params *types.Parameters) (uint8, error) {
	return 0, nil
}
func (disabledAgent) DeleteIPsecEndpoint(nodeID uint16) error { return nil }
func (disabledAgent) DeleteXFRM(reqID int) error              { return nil }
func (disabledAgent) DeleteXfrmPolicyOut(nodeID uint16, dst *net.IPNet) error {
	return nil
}

// newAgent returns a disabled IPsec agent on non-Linux platforms.
func newAgent(lc cell.Lifecycle, log *slog.Logger, jg job.Group, lns *node.LocalNodeStore, c config, em encrypt.EncryptMap) types.Agent {
	return disabledAgent{}
}

// noopCollector is a prometheus.Collector that exports no metrics.
type noopCollector struct{}

func (noopCollector) Describe(chan<- *prometheus.Desc) {}
func (noopCollector) Collect(chan<- prometheus.Metric) {}

// NewXFRMCollector returns a no-op collector on non-Linux platforms, where XFRM
// statistics are not available.
func NewXFRMCollector(log *slog.Logger) prometheus.Collector {
	return noopCollector{}
}

// ProbeXfrmStateOutputMask is a no-op on non-Linux platforms where the
// XFRM-based IPsec datapath is unavailable.
func ProbeXfrmStateOutputMask() error {
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ipsec

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

type xfrmCollector struct{}

func NewXFRMCollector(log *slog.Logger) prometheus.Collector {
	return xfrmCollector{}
}

func (xfrmCollector) Describe(ch chan<- *prometheus.Desc) {}

func (xfrmCollector) Collect(ch chan<- prometheus.Metric) {}

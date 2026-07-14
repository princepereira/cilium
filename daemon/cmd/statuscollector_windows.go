// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cmd

import (
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/status"
)

// windowsStatusCollector is a minimal stub implementation of
// status.StatusCollector for the Windows agent, which does not yet run the full
// status-collection machinery. It always reports an OK state so that the agent
// and kube-proxy health endpoints respond successfully.
type windowsStatusCollector struct{}

func (windowsStatusCollector) GetStatus(brief bool, requireK8sConnectivity bool) models.StatusResponse {
	return models.StatusResponse{
		Cilium: &models.Status{
			State: models.StatusStateOk,
			Msg:   "Cilium Windows agent is running",
		},
	}
}

func newWindowsStatusCollector() status.StatusCollector {
	return windowsStatusCollector{}
}

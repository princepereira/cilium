// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package vtep

import (
	"context"
	"log/slog"

	mapvtep "github.com/cilium/cilium/pkg/maps/vtep"
)

type vtepManagerConfig struct {
	vtepEndpoints []string
	vtepCIDRs     []string
	vtepMACs      []string
}

type vtepManager struct {
	logger  *slog.Logger
	vtepMap mapvtep.Map
	config  vtepManagerConfig
}

func (r *vtepManager) syncVTEP(context.Context) error { return nil }
func (r *vtepManager) setupVTEPMapping() error        { return nil }

//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/maps/vtep"
)

type vtepManager struct {
	logger  *slog.Logger
	vtepMap vtep.Map
	config  vtepManagerConfig
}

func (r *vtepManager) syncVTEP(ctx context.Context) error {
	return nil
}

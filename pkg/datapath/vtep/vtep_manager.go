// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

type vtepManagerConfig struct {
	vtepEndpoints []netip.Addr
	vtepCIDRs     []netip.Prefix
	vtepMACs      []mac.MAC
}

type vtepManager struct {
	logger  *slog.Logger
	vtepMap vtep.Map
	config  vtepManagerConfig
}

func (r *vtepManager) syncVTEP(ctx context.Context) error {
	r.logger.Debug("Syncing VTEP")

	if err := r.setupVTEPMapping(); err != nil {
		return err
	}

	if err := r.setupRouteToVTEPCidr(); err != nil {
		return err
	}

	return nil
}

func (r *vtepManager) setupVTEPMapping() error {
	for i, ep := range r.config.vtepEndpoints {
		r.logger.Debug(
			"Updating vtep map entry for VTEP",
			logfields.IPAddr, ep,
		)

		err := r.vtepMap.Update(r.config.vtepCIDRs[i], ep, r.config.vtepMACs[i])
		if err != nil {
			return fmt.Errorf("Unable to set up VTEP ipcache mappings: %w", err)
		}
	}
	return nil
}

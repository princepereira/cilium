// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package nat

import (
	"fmt"
	"net/netip"

	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
)

// CNCSnatConfig manages SNAT excluded subnets via cncshim on Windows.
type CNCSnatConfig struct {
	client *winDatapath.CNCClient
}

// NewCNCSnatConfig creates a new SNAT configuration manager for Windows.
func NewCNCSnatConfig(client *winDatapath.CNCClient) *CNCSnatConfig {
	return &CNCSnatConfig{client: client}
}

// AddExcludedSubnets adds SNAT excluded subnets via cncshim.
func (s *CNCSnatConfig) AddExcludedSubnets(subnets []netip.Prefix) error {
	api := s.client.API()
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}
	return api.AddSnatExcludedSubnets(subnets)
}

// DeleteExcludedSubnets removes SNAT excluded subnets via cncshim.
func (s *CNCSnatConfig) DeleteExcludedSubnets(subnets []netip.Prefix) error {
	api := s.client.API()
	if api == nil {
		return nil
	}
	return api.DeleteSnatExcludedSubnets(subnets)
}

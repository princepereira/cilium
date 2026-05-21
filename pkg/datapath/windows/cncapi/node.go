// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cncapi

import (
	"fmt"
	"net/netip"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

// GetNodeConfiguration retrieves the node configuration from the Windows
// datapath.
func (c *Client) GetNodeConfiguration() (*cncapi.NodeConfigInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return nil, fmt.Errorf("CNC API client is closed")
	}

	return c.api.GetNodeConfiguration()
}

// AddOrUpdateNodeConfiguration programs the node configuration into the
// Windows datapath.
func (c *Client) AddOrUpdateNodeConfiguration(config *cncapi.NodeConfigInfo) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Updating node configuration",
		"nativeInterfaces", len(config.NativeInterfaces),
		"directRoutingIfIndex", config.DirectRoutingInterface.IfIndex,
	)

	return c.api.AddOrUpdateNodeConfiguration(config)
}

// UpdateNodeConfigurationHashSeeds updates the hash seeds in the Windows
// datapath.
func (c *Client) UpdateNodeConfigurationHashSeeds(seeds *cncapi.HashSeeds) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.UpdateNodeConfigurationHashSeeds(seeds)
}

// SetNodeConfigurationInfraInterface sets the infrastructure NIC configuration
// in the Windows datapath.
func (c *Client) SetNodeConfigurationInfraInterface(info *cncapi.NodeInfraNicInfo) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Setting infra interface",
		"ifIndex", info.IfIndex,
	)

	return c.api.SetNodeConfigurationInfraInterface(info)
}

// SetTraceConfiguration sets the trace/observability configuration in the
// Windows datapath.
func (c *Client) SetTraceConfiguration(flags cncapi.NotifyEnableFlags, options *cncapi.TraceOptions) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.SetTraceConfiguration(flags, options)
}

// SetCtConfiguration sets the connection tracking configuration in the
// Windows datapath.
func (c *Client) SetCtConfiguration(config *cncapi.CTConfigInfo) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.SetCtConfiguration(config)
}

// SetGarbageCollectionConfiguration sets the GC configuration in the Windows
// datapath.
func (c *Client) SetGarbageCollectionConfiguration(config *cncapi.GarbageCollectionConfig) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.SetGarbageCollectionConfiguration(config)
}

// AddInternetExcludedSubnets adds subnets to the internet excluded list in the
// Windows datapath.
func (c *Client) AddInternetExcludedSubnets(subnets []netip.Prefix) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.AddInternetExcludedSubnets(subnets)
}

// DeleteInternetExcludedSubnets removes subnets from the internet excluded list
// in the Windows datapath.
func (c *Client) DeleteInternetExcludedSubnets(subnets []netip.Prefix) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.DeleteInternetExcludedSubnets(subnets)
}

// AddSnatExcludedSubnets adds subnets to the SNAT excluded list in the
// Windows datapath.
func (c *Client) AddSnatExcludedSubnets(subnets []netip.Prefix) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.AddSnatExcludedSubnets(subnets)
}

// DeleteSnatExcludedSubnets removes subnets from the SNAT excluded list in the
// Windows datapath.
func (c *Client) DeleteSnatExcludedSubnets(subnets []netip.Prefix) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.DeleteSnatExcludedSubnets(subnets)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cncapi

import (
	"fmt"
	"net/netip"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

// AddOrUpdateEndpointPolicies programs policy entries for an endpoint in the
// Windows datapath.
func (c *Client) AddOrUpdateEndpointPolicies(ifindex uint32, policies []cncapi.Policy) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Adding/updating endpoint policies",
		"ifindex", ifindex,
		"count", len(policies),
	)

	return c.api.AddOrUpdateEndpointPolicies(ifindex, policies)
}

// DeleteEndpointPolicies removes policy entries for an endpoint from the
// Windows datapath.
func (c *Client) DeleteEndpointPolicies(ifindex uint32, keys []cncapi.PolicyKey) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Deleting endpoint policies",
		"ifindex", ifindex,
		"count", len(keys),
	)

	return c.api.DeleteEndpointPolicies(ifindex, keys)
}

// GetEndpointPolicy retrieves a policy entry for an endpoint from the
// Windows datapath.
func (c *Client) GetEndpointPolicy(ifindex uint32, key *cncapi.PolicyKey) (*cncapi.Policy, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return nil, fmt.Errorf("CNC API client is closed")
	}

	return c.api.GetEndpointPolicy(ifindex, key)
}

// AddOrUpdateNeighbor programs a neighbor entry (IP -> MAC) in the Windows
// datapath.
func (c *Client) AddOrUpdateNeighbor(neighbor *cncapi.NeighborInfo) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Adding/updating neighbor",
		"ip", neighbor.IPAddress.String(),
		"mac", fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			neighbor.MACAddress[0], neighbor.MACAddress[1], neighbor.MACAddress[2],
			neighbor.MACAddress[3], neighbor.MACAddress[4], neighbor.MACAddress[5]),
	)

	return c.api.AddOrUpdateNeighbor(neighbor)
}

// DeleteNeighbor removes a neighbor entry from the Windows datapath.
func (c *Client) DeleteNeighbor(ip netip.Addr) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Deleting neighbor",
		"ip", ip.String(),
	)

	return c.api.DeleteNeighbor(ip)
}

// GetNeighbors retrieves all neighbor entries from the Windows datapath.
func (c *Client) GetNeighbors() ([]cncapi.NeighborInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return nil, fmt.Errorf("CNC API client is closed")
	}

	return c.api.GetNeighbors()
}

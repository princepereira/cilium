// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cncapi

import (
	"fmt"
	"net/netip"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

// SetIdentity programs an identity mapping (CIDR -> numeric identity) into
// the Windows datapath via the CNC API.
func (c *Client) SetIdentity(subnet netip.Prefix, identity uint32) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Setting identity",
		"subnet", subnet.String(),
		"identity", identity,
	)

	return c.api.SetIdentity(subnet, identity)
}

// GetIdentity retrieves the numeric identity for a given CIDR from the
// Windows datapath.
func (c *Client) GetIdentity(subnet netip.Prefix) (uint32, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return 0, fmt.Errorf("CNC API client is closed")
	}

	return c.api.GetIdentity(subnet)
}

// DeleteIdentity removes an identity mapping from the Windows datapath.
func (c *Client) DeleteIdentity(subnet netip.Prefix) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Deleting identity",
		"subnet", subnet.String(),
	)

	return c.api.DeleteIdentity(subnet)
}

// SyncIdentities performs a full sync of identity mappings. It sets the
// provided identities and deletes any that are no longer needed.
func (c *Client) SyncIdentities(desired map[netip.Prefix]uint32) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	var errs []error
	for subnet, identity := range desired {
		if err := c.api.SetIdentity(subnet, identity); err != nil {
			errs = append(errs, fmt.Errorf("set identity %s=%d: %w", subnet, identity, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sync identities: %d errors, first: %w", len(errs), errs[0])
	}
	return nil
}

// AddOrUpdateEndpoint programs or updates an endpoint in the Windows datapath.
func (c *Client) AddOrUpdateEndpoint(newEndpoint *cncapi.EndpointInfo, oldEndpoint *cncapi.EndpointInfo, disposition cncapi.CreationDisposition) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Adding/updating endpoint",
		"endpointID", newEndpoint.EndpointID,
		"ifIndex", newEndpoint.IfIndex,
		"identity", newEndpoint.Identity,
	)

	return c.api.AddOrUpdateEndpoint(newEndpoint, oldEndpoint, disposition)
}

// DeleteEndpoint removes an endpoint from the Windows datapath.
func (c *Client) DeleteEndpoint(address *cncapi.EndpointAddress) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	return c.api.DeleteEndpoint(address)
}

// GetEndpoint retrieves endpoint information from the Windows datapath.
func (c *Client) GetEndpoint(address *cncapi.EndpointAddress) (*cncapi.EndpointInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return nil, fmt.Errorf("CNC API client is closed")
	}

	return c.api.GetEndpoint(address)
}

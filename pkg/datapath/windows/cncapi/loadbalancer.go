// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cncapi

import (
	"fmt"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

// CreateLoadBalancerBackends creates load balancer backend entries in the
// Windows datapath.
func (c *Client) CreateLoadBalancerBackends(backends []cncapi.BackendInfo) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Creating LB backends",
		"count", len(backends),
	)

	return c.api.CreateLoadBalancerBackends(backends)
}

// CreateLoadBalancerService creates a load balancer service entry in the
// Windows datapath.
func (c *Client) CreateLoadBalancerService(serviceID uint16, info *cncapi.LoadBalancerInfo) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Creating LB service",
		"serviceID", serviceID,
		"frontend", fmt.Sprintf("%s:%d", info.Frontend.IPAddress, info.Frontend.Port),
		"serviceType", info.ServiceType,
	)

	return c.api.CreateLoadBalancerService(serviceID, info)
}

// UpdateLoadBalancerServiceBackends updates the backends of an existing
// load balancer service.
func (c *Client) UpdateLoadBalancerServiceBackends(serviceID uint16, info *cncapi.LoadBalancerInfo,
	newBackends []cncapi.BackendInfo, oldBackends []cncapi.BackendInfo) error {

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Updating LB service backends",
		"serviceID", serviceID,
		"newBackends", len(newBackends),
		"oldBackends", len(oldBackends),
	)

	return c.api.UpdateLoadBalancerServiceBackends(serviceID, info, newBackends, oldBackends)
}

// GetLoadBalancerService retrieves a load balancer service from the Windows
// datapath by its frontend.
func (c *Client) GetLoadBalancerService(frontend *cncapi.FrontendInfo) (*cncapi.LoadBalancerInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return nil, fmt.Errorf("CNC API client is closed")
	}

	return c.api.GetLoadBalancerService(frontend)
}

// DeleteLoadBalancerService removes a load balancer service from the Windows
// datapath.
func (c *Client) DeleteLoadBalancerService(serviceID uint16, info *cncapi.LoadBalancerInfo) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Deleting LB service",
		"serviceID", serviceID,
	)

	return c.api.DeleteLoadBalancerService(serviceID, info)
}

// DeleteLoadBalancerBackends removes load balancer backends from the Windows
// datapath.
func (c *Client) DeleteLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return fmt.Errorf("CNC API client is closed")
	}

	c.logger.Debug("Deleting LB backends",
		"addressFamily", addressFamily,
		"count", len(backendIDs),
	)

	return c.api.DeleteLoadBalancerBackends(addressFamily, backendIDs)
}

// GetLoadBalancerBackends retrieves load balancer backend information from the
// Windows datapath.
func (c *Client) GetLoadBalancerBackends(addressFamily uint16, backendIDs []uint32) ([]cncapi.BackendQueryResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.api == nil {
		return nil, fmt.Errorf("CNC API client is closed")
	}

	return c.api.GetLoadBalancerBackends(addressFamily, backendIDs)
}

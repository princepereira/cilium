// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ctmap

import (
	"fmt"

	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
	"github.com/princepereira/cncshim/pkg/cncapi"
)

// CNCCtConfig manages CT configuration via cncshim on Windows.
type CNCCtConfig struct {
	client *winDatapath.CNCClient
}

// NewCNCCtConfig creates a new CT configuration manager for Windows.
func NewCNCCtConfig(client *winDatapath.CNCClient) *CNCCtConfig {
	return &CNCCtConfig{client: client}
}

// SetConfiguration sets the CT configuration via cncshim.
func (c *CNCCtConfig) SetConfiguration(config *cncapi.CTConfigInfo) error {
	api := c.client.API()
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}
	return api.SetCtConfiguration(config)
}

// GetConfiguration gets the CT configuration via cncshim.
func (c *CNCCtConfig) GetConfiguration() (*cncapi.CTConfigInfo, error) {
	api := c.client.API()
	if api == nil {
		return nil, fmt.Errorf("CNC API client not initialized")
	}
	return api.GetCtConfiguration()
}

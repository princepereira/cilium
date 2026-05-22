// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package neighborsmap

import (
	"fmt"
	"net/netip"

	winDatapath "github.com/cilium/cilium/pkg/datapath/win"
	"github.com/princepereira/cncshim/pkg/cncapi"
)

// CNCNeighborsMap implements neighbor map operations using cncshim on Windows.
type CNCNeighborsMap struct {
	client *winDatapath.CNCClient
}

// NewCNCNeighborsMap creates a Windows CNC-backed neighbors map.
func NewCNCNeighborsMap(client *winDatapath.CNCClient) *CNCNeighborsMap {
	return &CNCNeighborsMap{client: client}
}

// AddOrUpdate adds or updates a neighbor entry via cncshim.
func (m *CNCNeighborsMap) AddOrUpdate(ip netip.Addr, mac [6]byte) error {
	api := m.client.API()
	if api == nil {
		return fmt.Errorf("CNC API client not initialized")
	}

	neighbor := &cncapi.NeighborInfo{
		IPAddress:  ip,
		MACAddress: cncapi.MACAddress(mac),
	}
	return api.AddOrUpdateNeighbor(neighbor)
}

// Delete removes a neighbor entry via cncshim.
func (m *CNCNeighborsMap) Delete(ip netip.Addr) error {
	api := m.client.API()
	if api == nil {
		return nil
	}
	return api.DeleteNeighbor(ip)
}

// GetAll retrieves all neighbor entries via cncshim.
func (m *CNCNeighborsMap) GetAll() ([]cncapi.NeighborInfo, error) {
	api := m.client.API()
	if api == nil {
		return nil, fmt.Errorf("CNC API client not initialized")
	}
	return api.GetNeighbors()
}

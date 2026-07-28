// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package hcs

import (
	"fmt"
	"log/slog"

	"github.com/Microsoft/hcsshim"
)

// winManager implements Manager on Windows using hcsshim.
type winManager struct {
	logger    *slog.Logger
	available bool
}

// New probes HCS availability and returns a Manager. It never returns nil; if
// HCS cannot be queried the Manager is disabled (Available() == false) and its
// operations return ErrUnsupported.
func New(logger *slog.Logger) Manager {
	m := &winManager{logger: logger}
	// A container enumeration is the cheapest way to confirm the HCS service
	// responds. An empty result with no error means HCS is usable.
	if _, err := hcsshim.GetContainers(hcsshim.ComputeSystemQuery{}); err != nil {
		if logger != nil {
			logger.Warn("Host Compute System (HCS) unavailable; "+
				"Windows container correlation disabled", "error", err)
		}
		return m
	}
	m.available = true
	if logger != nil {
		logger.Info("Host Compute System (HCS) available; Windows container correlation enabled")
	}
	return m
}

func (m *winManager) Available() bool { return m.available }

func (m *winManager) ListContainers() ([]ContainerInfo, error) {
	if !m.available {
		return nil, ErrUnsupported
	}
	props, err := hcsshim.GetContainers(hcsshim.ComputeSystemQuery{})
	if err != nil {
		return nil, fmt.Errorf("hcs: list containers: %w", err)
	}
	out := make([]ContainerInfo, 0, len(props))
	for _, p := range props {
		out = append(out, ContainerInfo{
			ID:         p.ID,
			Name:       p.Name,
			State:      p.State,
			SystemType: p.SystemType,
			Owner:      p.Owner,
		})
	}
	return out, nil
}

func (m *winManager) GetContainer(id string) (ContainerInfo, error) {
	if !m.available {
		return ContainerInfo{}, ErrUnsupported
	}
	props, err := hcsshim.GetContainers(hcsshim.ComputeSystemQuery{IDs: []string{id}})
	if err != nil {
		return ContainerInfo{}, fmt.Errorf("hcs: get container %q: %w", id, err)
	}
	if len(props) == 0 {
		return ContainerInfo{}, fmt.Errorf("hcs: container %q not found", id)
	}
	p := props[0]
	return ContainerInfo{
		ID:         p.ID,
		Name:       p.Name,
		State:      p.State,
		SystemType: p.SystemType,
		Owner:      p.Owner,
	}, nil
}

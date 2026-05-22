// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package win

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

var Cell = cell.Module(
	"datapath-win",
	"Windows CNC datapath",
	cell.Provide(newCNCClient),
)

// CNCClient wraps the cncshim CNCApi client and manages its lifecycle.
type CNCClient struct {
	mu     sync.Mutex
	api    cncapi.CNCApi
	logger *slog.Logger
}

type cncClientParams struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
}

func newCNCClient(p cncClientParams) *CNCClient {
	c := &CNCClient{
		logger: p.Log,
	}
	p.Lifecycle.Append(c)
	return c
}

func (c *CNCClient) Start(cell.HookContext) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	client, err := cncapi.New()
	if err != nil {
		return fmt.Errorf("failed to initialize CNC API client: %w", err)
	}
	c.api = client
	c.logger.Info("CNC API client initialized",
		"shimVersion", cncapi.GetVersion(),
		"cncApiVersion", cncapi.GetCNCApiVersion(),
	)
	return nil
}

func (c *CNCClient) Stop(cell.HookContext) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.api != nil {
		if err := c.api.Close(); err != nil {
			c.logger.Warn("Failed to close CNC API client", "error", err)
		}
		c.api = nil
	}
	return nil
}

// API returns the underlying CNCApi interface. Must only be called after Start.
func (c *CNCClient) API() cncapi.CNCApi {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.api
}

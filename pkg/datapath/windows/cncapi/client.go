// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cncapi

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

// Client wraps the cncshim CNCApi interface and provides a managed lifecycle
// for the Windows CNC API connection.
type Client struct {
	mu     sync.RWMutex
	api    cncapi.CNCApi
	logger *slog.Logger
}

// NewClient creates a new CNC API client, initializing the connection to
// cncapi.dll.
func NewClient(logger *slog.Logger) (*Client, error) {
	api, err := cncapi.New()
	if err != nil {
		return nil, fmt.Errorf("initializing CNC API client: %w", err)
	}

	logger.Info("CNC API client initialized",
		"shimVersion", cncapi.GetVersion(),
		"cncApiVersion", cncapi.GetCNCApiVersion(),
	)

	return &Client{
		api:    api,
		logger: logger,
	}, nil
}

// Close releases resources held by the CNC API client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.api != nil {
		err := c.api.Close()
		c.api = nil
		return err
	}
	return nil
}

// API returns the underlying CNCApi interface for direct access.
// The caller must not close the returned interface.
func (c *Client) API() cncapi.CNCApi {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.api
}

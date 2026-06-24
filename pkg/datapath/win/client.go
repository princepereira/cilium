// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package win

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/cell"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

var Cell = cell.Module(
	"datapath-win",
	"Windows CNC datapath",
	cell.Provide(newCNCClient),
)

// CNCClient wraps the cncshim CNCApi client and manages its lifecycle.
// It retries connecting to cncshim in the background if the initial attempt fails.
type CNCClient struct {
	mu       sync.Mutex
	api      cncapi.CNCApi
	logger   *slog.Logger
	ready    chan struct{}
	cancelFn context.CancelFunc
}

type cncClientParams struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
}

func newCNCClient(p cncClientParams) *CNCClient {
	c := &CNCClient{
		logger: p.Log,
		ready:  make(chan struct{}),
	}
	p.Lifecycle.Append(c)
	return c
}

func (c *CNCClient) Start(cell.HookContext) error {
	c.mu.Lock()

	client, err := cncapi.New()
	if err != nil {
		c.mu.Unlock()
		c.logger.Warn("CNC API not available, will retry in background",
			"error", err)

		ctx, cancel := context.WithCancel(context.Background())
		c.cancelFn = cancel
		go c.retryConnect(ctx)
		return nil
	}

	c.api = client
	c.mu.Unlock()
	close(c.ready)
	c.logger.Info("CNC API client initialized",
		"shimVersion", cncapi.GetVersion(),
		"cncApiVersion", cncapi.GetCNCApiVersion(),
	)
	return nil
}

func (c *CNCClient) retryConnect(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			client, err := cncapi.New()
			if err != nil {
				c.logger.Warn("CNC API retry failed", "error", err)
				continue
			}
			c.mu.Lock()
			c.api = client
			c.mu.Unlock()
			close(c.ready)
			c.logger.Info("CNC API client initialized (retry succeeded)",
				"shimVersion", cncapi.GetVersion(),
				"cncApiVersion", cncapi.GetCNCApiVersion(),
			)
			return
		}
	}
}

func (c *CNCClient) Stop(cell.HookContext) error {
	if c.cancelFn != nil {
		c.cancelFn()
	}

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

// API returns the underlying CNCApi interface. Returns nil if not yet connected.
func (c *CNCClient) API() cncapi.CNCApi {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.api
}

// Ready returns a channel that is closed when the CNC client is connected.
func (c *CNCClient) Ready() <-chan struct{} {
	return c.ready
}

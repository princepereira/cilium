// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package cni

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

type cniConfigManager struct {
	config      Config
	debug       bool
	cniConfDir  string
	cniConfFile string
	logger      *slog.Logger
	ctx         context.Context
	doneFunc    context.CancelFunc
	controller  *controller.Manager
	status      atomic.Pointer[models.Status]
}

func (c *cniConfigManager) GetMTU() int                         { return 0 }
func (c *cniConfigManager) GetChainingMode() string             { return c.config.CNIChainingMode }
func (c *cniConfigManager) Status() *models.Status              { return c.status.Load() }
func (c *cniConfigManager) GetCustomNetConf() *cnitypes.NetConf { return nil }
func (c *cniConfigManager) ExternalRoutingEnabled() bool        { return c.config.CNIExternalRouting }

func (c *cniConfigManager) Start(cell.HookContext) error {
	if c.status.Load() == nil {
		c.status.Store(&models.Status{Msg: "CNI configuration management is unsupported on windows", State: models.StatusStateDisabled})
	}
	return nil
}

func (c *cniConfigManager) Stop(cell.HookContext) error { return nil }

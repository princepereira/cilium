// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package agent

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
)

var Cell = cell.Module(
	"monitor-agent",
	"Consumes the cilium events map and distributes those and other agent events",
	cell.Provide(func() Agent { return noopAgent{} }),
	cell.Config(defaultConfig),
)

type AgentConfig struct {
	EnableMonitor    bool
	MonitorQueueSize int
}

var defaultConfig = AgentConfig{EnableMonitor: false}

func (def AgentConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-monitor", def.EnableMonitor, "Enable the monitor unix domain socket server")
	flags.Int("monitor-queue-size", def.MonitorQueueSize, "Size of the event queue when reading monitor events")
}

type Agent interface {
	AttachToEventsMap(nPages int) error
	SendEvent(typ int, event any) error
	RegisterNewListener(newListener listener.MonitorListener)
	RemoveListener(ml listener.MonitorListener)
	RegisterNewConsumer(newConsumer consumer.MonitorConsumer)
	RemoveConsumer(mc consumer.MonitorConsumer)
	State() *models.MonitorStatus
}

type noopAgent struct{}

func (noopAgent) AttachToEventsMap(int) error                         { return nil }
func (noopAgent) SendEvent(int, any) error                            { return nil }
func (noopAgent) RegisterNewListener(listener.MonitorListener)        {}
func (noopAgent) RemoveListener(listener.MonitorListener)             {}
func (noopAgent) RegisterNewConsumer(consumer.MonitorConsumer)        {}
func (noopAgent) RemoveConsumer(consumer.MonitorConsumer)             {}
func (noopAgent) State() *models.MonitorStatus                        { return &models.MonitorStatus{} }
func ServeMonitorAPI(context.Context, *slog.Logger, Agent, int) error { return nil }

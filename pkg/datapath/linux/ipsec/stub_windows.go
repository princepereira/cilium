// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package ipsec

import (
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/node"
)

type Config = types.Config
type Agent = types.Agent

type UserConfig struct{}

type config struct{ UserConfig }

func (config) Enabled() bool                                  { return false }
func (config) UseCiliumInternalIP() bool                      { return false }
func (config) DNSProxyInsecureSkipTransparentModeCheckEnabled() bool { return false }

type params struct{}

var Cell = cell.Module(
	"ipsec-agent",
	"Handles initial key setup and knows the key size",
)

var OperatorCell = cell.Module("ipsec-operator", "IPsec operator configuration")

type agent struct{}

func newAgent(cell.Lifecycle, *slog.Logger, job.Group, *node.LocalNodeStore, config, encrypt.EncryptMap) types.Agent {
	return &agent{}
}

func ProbeXfrmStateOutputMask() error { return nil }
func NewXFRMCollector(*slog.Logger) prometheus.Collector { return nil }

func NewTestIPsecAgent(any) types.Agent { return &agent{} }

func (a *agent) Enabled() bool                                            { return false }
func (a *agent) AuthKeySize() int                                         { return 0 }
func (a *agent) SPI() uint8                                               { return 0 }
func (a *agent) StartBackgroundJobs(node.Handler, <-chan struct{}) error  { return nil }
func (a *agent) UpsertIPsecEndpoint(*types.Parameters) (uint8, error)     { return 0, nil }
func (a *agent) DeleteIPsecEndpoint(uint16) error                         { return nil }
func (a *agent) DeleteXFRM(int) error                                     { return nil }
func (a *agent) DeleteXfrmPolicyOut(uint16, *net.IPNet) error             { return nil }

func buildConfigFrom(uc UserConfig, _ any) config { return config{UserConfig: uc} }
func newIPsecConfig(c config) types.Config        { return c }

func newIPsecAgent(params) (out struct {
	cell.Out
	types.Agent
	defines.NodeOut
}) {
	out.Agent = &agent{}
	return
}

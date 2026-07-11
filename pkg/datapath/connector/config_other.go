// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package connector

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type Config interface {
	Reinitialize() error
	GetPodDeviceHeadroom() uint16
	GetPodDeviceTailroom() uint16
	GetConfiguredMode() Mode
	GetOperationalMode() Mode
	NewLinkPair(cfg LinkConfig, sysctl sysctl.Sysctl) (LinkPair, error)
	GetLinkCompatibility(ifName string) (Mode, bool, error)
}

type config struct {
	configuredMode  Mode
	operationalMode Mode
}

func (cc *config) Reinitialize() error {
	return nil
}

func (cc *config) GetPodDeviceHeadroom() uint16 {
	return 0
}

func (cc *config) GetPodDeviceTailroom() uint16 {
	return 0
}

func (cc *config) GetConfiguredMode() Mode {
	return cc.configuredMode
}

func (cc *config) GetOperationalMode() Mode {
	return cc.operationalMode
}

func (cc *config) NewLinkPair(cfg LinkConfig, sysctl sysctl.Sysctl) (LinkPair, error) {
	return nil, fmt.Errorf("not supported on this platform")
}

func (cc *config) GetLinkCompatibility(ifName string) (Mode, bool, error) {
	return ModeUnspec, false, fmt.Errorf("not supported on this platform")
}

type connectorParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Log          *slog.Logger
	DaemonConfig *option.DaemonConfig
	WgAgent      wgTypes.Agent
	TunnelConfig tunnel.Config
	KPRConfig    kpr.KPRConfig
}

func newConfig(p connectorParams) (*config, error) {
	configuredMode := ModeUnspec
	if p.DaemonConfig != nil {
		configuredMode = ModeByName(p.DaemonConfig.DatapathMode)
	}

	return &config{
		configuredMode:  configuredMode,
		operationalMode: configuredMode,
	}, nil
}

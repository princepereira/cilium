// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package iptables

import "net/netip"

// Manager manages iptables rules.
type Manager interface {
	InstallProxyRules(proxyPort uint16, name string)
	SupportsOriginalSourceAddr() bool
	GetProxyPorts() map[string]uint16
	InstallNoTrackRules(ip netip.Addr, port uint16)
	RemoveNoTrackRules(ip netip.Addr, port uint16)
	AddNoTrackHostPorts(namespace, name string, ports []string)
	RemoveNoTrackHostPorts(namespace, name string)
}

type manager struct{}

func newManager() Manager {
	return manager{}
}

func (m manager) InstallProxyRules(proxyPort uint16, name string) {}

func (m manager) SupportsOriginalSourceAddr() bool {
	return false
}

func (m manager) GetProxyPorts() map[string]uint16 {
	return map[string]uint16{}
}

func (m manager) InstallNoTrackRules(ip netip.Addr, port uint16) {}

func (m manager) RemoveNoTrackRules(ip netip.Addr, port uint16) {}

func (m manager) AddNoTrackHostPorts(namespace, name string, ports []string) {}

func (m manager) RemoveNoTrackHostPorts(namespace, name string) {}

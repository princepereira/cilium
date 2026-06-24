// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package iptables

import "net/netip"

type Manager interface {
	InstallProxyRules(proxyPort uint16, name string)
	SupportsOriginalSourceAddr() bool
	GetProxyPorts() map[string]uint16
	InstallNoTrackRules(ip netip.Addr, port uint16)
	RemoveNoTrackRules(ip netip.Addr, port uint16)
	AddNoTrackHostPorts(namespace, name string, ports []string)
	RemoveNoTrackHostPorts(namespace, name string)
}

type noopManager struct{}

func newManager() Manager                                    { return noopManager{} }
func (noopManager) InstallProxyRules(uint16, string)        {}
func (noopManager) SupportsOriginalSourceAddr() bool        { return false }
func (noopManager) GetProxyPorts() map[string]uint16        { return map[string]uint16{} }
func (noopManager) InstallNoTrackRules(netip.Addr, uint16)  {}
func (noopManager) RemoveNoTrackRules(netip.Addr, uint16)   {}
func (noopManager) AddNoTrackHostPorts(string, string, []string) {}
func (noopManager) RemoveNoTrackHostPorts(string, string)   {}

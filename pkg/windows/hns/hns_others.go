// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package hns

import "log/slog"

// stubManager is the disabled Manager used on non-Windows platforms. Every
// mutating operation reports ErrUnsupported and Available() is false.
type stubManager struct{}

// New returns a disabled Manager. HNS/HCN only exists on Windows.
func New(logger *slog.Logger) Manager {
	if logger != nil {
		logger.Debug("HNS/HCN not supported on this platform; using disabled datapath manager")
	}
	return stubManager{}
}

func (stubManager) Available() bool                                  { return false }
func (stubManager) GetNetworkID(string) (string, error)              { return "", ErrUnsupported }
func (stubManager) CreateEndpoint(EndpointSpec) (string, error)      { return "", ErrUnsupported }
func (stubManager) DeleteEndpoint(string) error                      { return ErrUnsupported }
func (stubManager) AttachEndpointToNamespace(string, string) error   { return ErrUnsupported }
func (stubManager) CreateNamespace() (string, error)                 { return "", ErrUnsupported }
func (stubManager) DeleteNamespace(string) error                     { return ErrUnsupported }
func (stubManager) AddRemoteNodeRoute(string, RemoteNodeRoute) error { return ErrUnsupported }
func (stubManager) RemoveRemoteNodeRoute(string, RemoteNodeRoute) error {
	return ErrUnsupported
}

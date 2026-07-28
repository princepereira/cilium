// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package hcs

import "log/slog"

// stubManager is the disabled Manager used on non-Windows platforms.
type stubManager struct{}

// New returns a disabled Manager. HCS only exists on Windows.
func New(logger *slog.Logger) Manager {
	if logger != nil {
		logger.Debug("HCS not supported on this platform; using disabled container manager")
	}
	return stubManager{}
}

func (stubManager) Available() bool                          { return false }
func (stubManager) ListContainers() ([]ContainerInfo, error) { return nil, ErrUnsupported }
func (stubManager) GetContainer(string) (ContainerInfo, error) {
	return ContainerInfo{}, ErrUnsupported
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package hcs provides native Windows container (Host Compute System)
// operations relevant to the Cilium datapath: enumerating and inspecting the
// containers running on the node so that endpoints can be correlated with
// their workloads. It wraps github.com/Microsoft/hcsshim on Windows and
// degrades to a disabled no-op implementation on every other platform.
//
// Only read-only, correlation-oriented operations are exposed; Cilium does not
// create or manage container lifecycles (that is the CRI/CNI's job).
package hcs

import "errors"

// ErrUnsupported is returned on non-Windows platforms (or when HCS is
// unavailable) for operations that require the Host Compute System.
var ErrUnsupported = errors.New("HCS is not available on this platform")

// ContainerInfo is a platform-neutral view of a Host Compute System container.
type ContainerInfo struct {
	ID         string
	Name       string
	State      string
	SystemType string
	Owner      string
}

// Manager provides native Windows container query operations.
//
// The Windows implementation is backed by hcsshim; all other platforms use a
// disabled stub whose methods return ErrUnsupported and whose Available()
// reports false.
type Manager interface {
	// Available reports whether the Host Compute System is usable on this host.
	Available() bool

	// ListContainers returns the containers currently known to HCS.
	ListContainers() ([]ContainerInfo, error)

	// GetContainer returns the properties of a single container by ID.
	GetContainer(id string) (ContainerInfo, error)
}

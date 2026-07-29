// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package hns provides native Windows host-networking (HNS/HCN) operations for
// the Cilium datapath: networks, namespaces, endpoints and policies. It wraps
// github.com/Microsoft/hnslib (the Host Compute Network API) on Windows and
// degrades to a disabled no-op implementation on every other platform, so the
// cross-platform datapath can depend on it unconditionally.
//
// Implementations degrade gracefully at runtime as well: if the HCN service is
// not present (e.g. a developer machine, or Windows without the container
// networking feature), Available() reports false and mutating operations
// return ErrUnsupported. Callers treat programming failures as best-effort.
package hns

import (
	"errors"
	"net/netip"
)

// ErrUnsupported is returned by mutating operations when the HNS/HCN service is
// unavailable (non-Windows platforms, or Windows without container networking).
var ErrUnsupported = errors.New("HNS (HCN) is not available on this platform")

// RemoteNodeRoute describes an overlay route to a remote node's pod CIDR. On
// Windows it is programmed as an HNS RemoteSubnetRoute network policy so that
// traffic to the remote pod CIDR is encapsulated towards the remote node's
// underlay (provider) address.
type RemoteNodeRoute struct {
	// DestinationPrefix is the remote node's pod allocation CIDR.
	DestinationPrefix netip.Prefix
	// ProviderAddress is the remote node's underlay/internal IP (the tunnel
	// endpoint that the destination prefix is reachable through).
	ProviderAddress netip.Addr
	// IsolationID is the overlay isolation ID (VSID/VNI) of the network.
	IsolationID uint16
}

// Valid reports whether the route carries a usable destination prefix and
// provider address. Invalid routes are skipped rather than programmed.
func (r RemoteNodeRoute) Valid() bool {
	return r.DestinationPrefix.IsValid() && r.ProviderAddress.IsValid()
}

// EndpointSpec describes an HNS endpoint to create on a given network and,
// optionally, attach to a namespace.
type EndpointSpec struct {
	// Name is the endpoint name (typically the Cilium endpoint / container id).
	Name string
	// NetworkName is the HNS network to create the endpoint on.
	NetworkName string
	// IPs are the endpoint IP addresses (with prefix length).
	IPs []netip.Prefix
	// MACAddress is an optional MAC address ("aa-bb-cc-dd-ee-ff").
	MACAddress string
	// NamespaceID, when set, is the HCN namespace to attach the endpoint to.
	NamespaceID string
}

// Manager provides native Windows host-networking (HNS/HCN) operations.
//
// The interface is platform-neutral; the Windows implementation is backed by
// hnslib/hcn, while all other platforms use a disabled stub whose mutating
// methods return ErrUnsupported and whose Available() reports false.
type Manager interface {
	// Available reports whether the HCN service is usable on this host.
	Available() bool

	// GetNetworkID resolves an HNS network name to its GUID.
	GetNetworkID(name string) (string, error)

	// CreateEndpoint creates an HNS endpoint from spec and, if a namespace is
	// set, attaches it. It returns the created endpoint's GUID.
	CreateEndpoint(spec EndpointSpec) (string, error)

	// DeleteEndpoint deletes an HNS endpoint by GUID or name.
	DeleteEndpoint(idOrName string) error

	// AttachEndpointToNamespace attaches an existing endpoint to a namespace.
	AttachEndpointToNamespace(namespaceID, endpointID string) error

	// CreateNamespace creates a guest HCN namespace and returns its GUID.
	CreateNamespace() (string, error)

	// DeleteNamespace deletes an HCN namespace by GUID.
	DeleteNamespace(namespaceID string) error

	// AddRemoteNodeRoute programs a RemoteSubnetRoute policy on the network for
	// a remote node's pod CIDR.
	AddRemoteNodeRoute(networkName string, route RemoteNodeRoute) error

	// RemoveRemoteNodeRoute removes a previously-added RemoteSubnetRoute policy.
	RemoveRemoteNodeRoute(networkName string, route RemoteNodeRoute) error
}

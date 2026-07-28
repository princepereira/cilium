// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package hns

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Microsoft/hnslib/hcn"
)

// winManager implements Manager on Windows using the HCN API (hnslib/hcn).
type winManager struct {
	logger    *slog.Logger
	available bool
}

// New probes the HCN service and returns a Manager. If HCN is unavailable the
// returned Manager is disabled (Available() == false) and mutating operations
// return ErrUnsupported, so the agent still starts on hosts without container
// networking.
func New(logger *slog.Logger) Manager {
	if logger == nil {
		logger = slog.Default()
	}
	m := &winManager{logger: logger}
	if _, err := hcn.GetGlobals(); err != nil {
		logger.Warn("HNS/HCN service unavailable; "+
			"Windows datapath network operations will be best-effort no-ops",
			"error", err,
		)
		return m
	}
	m.available = true
	logger.Info("HNS/HCN service available; native Windows datapath enabled")
	return m
}

func (m *winManager) Available() bool { return m.available }

func (m *winManager) GetNetworkID(name string) (string, error) {
	if !m.available {
		return "", ErrUnsupported
	}
	network, err := hcn.GetNetworkByName(name)
	if err != nil {
		return "", fmt.Errorf("hns: get network %q: %w", name, err)
	}
	return network.Id, nil
}

func (m *winManager) CreateEndpoint(spec EndpointSpec) (string, error) {
	if !m.available {
		return "", ErrUnsupported
	}
	network, err := hcn.GetNetworkByName(spec.NetworkName)
	if err != nil {
		return "", fmt.Errorf("hns: get network %q: %w", spec.NetworkName, err)
	}

	ep := &hcn.HostComputeEndpoint{
		Name:               spec.Name,
		HostComputeNetwork: network.Id,
		MacAddress:         spec.MACAddress,
		SchemaVersion:      hcn.V2SchemaVersion(),
	}
	for _, p := range spec.IPs {
		if !p.IsValid() {
			continue
		}
		ep.IpConfigurations = append(ep.IpConfigurations, hcn.IpConfig{
			IpAddress:    p.Addr().String(),
			PrefixLength: uint8(p.Bits()),
		})
	}

	created, err := network.CreateEndpoint(ep)
	if err != nil {
		return "", fmt.Errorf("hns: create endpoint %q: %w", spec.Name, err)
	}
	if spec.NamespaceID != "" {
		if err := created.NamespaceAttach(spec.NamespaceID); err != nil {
			return created.Id, fmt.Errorf("hns: attach endpoint %q to namespace %q: %w",
				created.Id, spec.NamespaceID, err)
		}
	}
	return created.Id, nil
}

func (m *winManager) DeleteEndpoint(idOrName string) error {
	if !m.available {
		return ErrUnsupported
	}
	ep, err := m.lookupEndpoint(idOrName)
	if err != nil {
		return err
	}
	if err := ep.Delete(); err != nil {
		return fmt.Errorf("hns: delete endpoint %q: %w", idOrName, err)
	}
	return nil
}

func (m *winManager) lookupEndpoint(idOrName string) (*hcn.HostComputeEndpoint, error) {
	if ep, err := hcn.GetEndpointByID(idOrName); err == nil {
		return ep, nil
	}
	ep, err := hcn.GetEndpointByName(idOrName)
	if err != nil {
		return nil, fmt.Errorf("hns: endpoint %q not found: %w", idOrName, err)
	}
	return ep, nil
}

func (m *winManager) AttachEndpointToNamespace(namespaceID, endpointID string) error {
	if !m.available {
		return ErrUnsupported
	}
	if err := hcn.AddNamespaceEndpoint(namespaceID, endpointID); err != nil {
		return fmt.Errorf("hns: add endpoint %q to namespace %q: %w", endpointID, namespaceID, err)
	}
	return nil
}

func (m *winManager) CreateNamespace() (string, error) {
	if !m.available {
		return "", ErrUnsupported
	}
	ns := hcn.NewNamespace(hcn.NamespaceTypeGuest)
	created, err := ns.Create()
	if err != nil {
		return "", fmt.Errorf("hns: create namespace: %w", err)
	}
	return created.Id, nil
}

func (m *winManager) DeleteNamespace(namespaceID string) error {
	if !m.available {
		return ErrUnsupported
	}
	ns, err := hcn.GetNamespaceByID(namespaceID)
	if err != nil {
		return fmt.Errorf("hns: namespace %q not found: %w", namespaceID, err)
	}
	if err := ns.Delete(); err != nil {
		return fmt.Errorf("hns: delete namespace %q: %w", namespaceID, err)
	}
	return nil
}

func (m *winManager) AddRemoteNodeRoute(networkName string, route RemoteNodeRoute) error {
	return m.modifyRemoteNodeRoute(networkName, route, true)
}

func (m *winManager) RemoveRemoteNodeRoute(networkName string, route RemoteNodeRoute) error {
	return m.modifyRemoteNodeRoute(networkName, route, false)
}

func (m *winManager) modifyRemoteNodeRoute(networkName string, route RemoteNodeRoute, add bool) error {
	if !m.available {
		return ErrUnsupported
	}
	if !route.Valid() {
		return fmt.Errorf("hns: invalid remote node route %+v", route)
	}
	network, err := hcn.GetNetworkByName(networkName)
	if err != nil {
		return fmt.Errorf("hns: get network %q: %w", networkName, err)
	}

	settings := hcn.RemoteSubnetRoutePolicySetting{
		DestinationPrefix: route.DestinationPrefix.String(),
		IsolationId:       route.IsolationID,
		ProviderAddress:   route.ProviderAddress.String(),
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("hns: marshal remote subnet route: %w", err)
	}
	req := hcn.PolicyNetworkRequest{
		Policies: []hcn.NetworkPolicy{{
			Type:     hcn.RemoteSubnetRoute,
			Settings: raw,
		}},
	}

	if add {
		if err := network.AddPolicy(req); err != nil {
			return fmt.Errorf("hns: add remote subnet route %s via %s: %w",
				route.DestinationPrefix, route.ProviderAddress, err)
		}
		return nil
	}
	if err := network.RemovePolicy(req); err != nil {
		return fmt.Errorf("hns: remove remote subnet route %s: %w", route.DestinationPrefix, err)
	}
	return nil
}

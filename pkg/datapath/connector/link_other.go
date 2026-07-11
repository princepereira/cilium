// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package connector

import (
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/netns"
)

// LinkConfig contains the GRO/GSO, MTU values and buffer margins to be configured on
// both sides of the created veth or netkit pair.
type LinkConfig struct {
	// EndpointID defines the container ID to which we are creating a new
	// linkpair. Set this if you want the connector to generate interface
	// names itself. Otherwise, set HostIfName and PeerIfName.
	EndpointID string

	// HostIfName defines the interface name as seen in the host namespace.
	HostIfName string

	// PeerIfName defines the interface name as seen in the container namespace.
	PeerIfName string

	// PeerNamespace defines the namespace the peer link should be moved into.
	PeerNamespace *netns.NetNS

	GROIPv6MaxSize int
	GSOIPv6MaxSize int

	GROIPv4MaxSize int
	GSOIPv4MaxSize int

	DeviceMTU      int
	DeviceHeadroom uint16
	DeviceTailroom uint16
}

type LinkPair interface {
	GetHostLink() netlink.Link
	GetPeerLink() netlink.Link
	GetMode() Mode
	Delete() error
}

func NewLinkPair(
	log *slog.Logger,
	mode Mode,
	cfg LinkConfig,
	sysctl sysctl.Sysctl,
) (*linkPair, error) {
	return nil, fmt.Errorf("not supported on this platform")
}

func DeleteLinkPair(cfg LinkConfig) error {
	return fmt.Errorf("not supported on this platform")
}

type linkPair struct {
	hostLink netlink.Link
	peerLink netlink.Link
	mode     Mode
}

func (lp *linkPair) GetHostLink() netlink.Link {
	return lp.hostLink
}

func (lp *linkPair) GetPeerLink() netlink.Link {
	return lp.peerLink
}

func (lp *linkPair) GetMode() Mode {
	return lp.mode
}

func (lp *linkPair) Delete() error {
	return fmt.Errorf("not supported on this platform")
}

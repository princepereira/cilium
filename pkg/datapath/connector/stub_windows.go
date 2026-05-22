// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package connector

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/netns"
)

const (
	HostInterfacePrefix    = "lxc"
	temporaryInterfacePrefix = "tmp"
	ciliumCNIAltName      = "cilium_cni"
	windowsIfNameSize     = 16
)

func IsCiliumManagedLink(link netlink.Link) bool {
	for _, altName := range link.Attrs().AltNames {
		if altName == CniAltName(link.Attrs().Name) {
			return true
		}
	}
	return false
}

func CniAltName(ifName string) string { return fmt.Sprintf("%s:%s", ciliumCNIAltName, ifName) }

func Endpoint2IfName(endpointID string) string {
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(endpointID)))
	truncateLength := uint(windowsIfNameSize - len(temporaryInterfacePrefix) - 1)
	return HostInterfacePrefix + truncateString(sum, truncateLength)
}

func Endpoint2TempIfName(endpointID string) string { return temporaryInterfacePrefix + truncateString(endpointID, 5) }

func truncateString(epID string, maxLen uint) string {
	if maxLen <= uint(len(epID)) {
		return epID[:maxLen]
	}
	return epID
}

func DisableRpFilter(sysctl sysctl.Sysctl, ifName string) error {
	return sysctl.Disable([]string{"net", "ipv4", "conf", ifName, "rp_filter"})
}

type LinkConfig struct {
	EndpointID       string
	HostIfName       string
	PeerIfName       string
	PeerNamespace    *netns.NetNS
	GROIPv6MaxSize   int
	GSOIPv6MaxSize   int
	GROIPv4MaxSize   int
	GSOIPv4MaxSize   int
	DeviceMTU        int
	DeviceHeadroom   uint16
	DeviceTailroom   uint16
}

type LinkPair interface {
	GetHostLink() netlink.Link
	GetPeerLink() netlink.Link
	GetMode() Mode
	Delete() error
}

type linkPair struct {
	hostLink netlink.Link
	peerLink netlink.Link
	mode     Mode
}

func (lp *linkPair) GetHostLink() netlink.Link { return lp.hostLink }
func (lp *linkPair) GetPeerLink() netlink.Link { return lp.peerLink }
func (lp *linkPair) GetMode() Mode             { return lp.mode }
func (lp *linkPair) Delete() error             { return nil }

func NewLinkPair(*slog.Logger, Mode, LinkConfig, sysctl.Sysctl) (*linkPair, error) {
	return &linkPair{}, nil
}

func DeleteLinkPair(LinkConfig) error { return nil }

func renameIfNeeded(finalName, currentName string, _ *netns.NetNS) (string, error) {
	if finalName == "" {
		return currentName, nil
	}
	return finalName, nil
}

func markOwned(*netns.NetNS, string) error { return nil }

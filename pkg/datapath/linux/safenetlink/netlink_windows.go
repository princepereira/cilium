// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

// This file provides the Windows implementations of the safenetlink wrappers.
//
// vishvananda/netlink is Linux-only, so on Windows there is no netlink socket to
// talk to. Instead, the interface- and address-enumeration helpers are backed by
// the Go standard library net package. On Windows, net.Interfaces /
// net.InterfaceByName / (*net.Interface).Addrs resolve through the
// GetAdaptersAddresses / GetIfTable2 Win32 APIs (iphlpapi.dll / netioapi.h),
// which is the portable equivalent of the netlink enumeration used on Linux.
//
// Mutating operations (route/rule/neighbor/xfrm/socket-diag programming) have no
// portable equivalent and are implemented in dedicated *_windows.go backends as
// they are ported; until then they return netlink.ErrNotImplemented, mirroring
// the behaviour of the generic non-linux stubs in netlink_unspecified.go.

package safenetlink

import (
	"net"

	"github.com/vishvananda/netlink"
)

// Address-family selectors, using the same numeric convention as the Linux
// netlink FAMILY_* constants (which are not defined outside the linux build).
const (
	familyAll = 0  // AF_UNSPEC
	familyV4  = 2  // AF_INET
	familyV6  = 10 // AF_INET6
)

// linkFromInterface converts a net.Interface into a netlink.Link. It returns a
// *netlink.Device, the generic concrete Link type that carries only LinkAttrs
// (which is all the information the standard library exposes).
func linkFromInterface(iface net.Interface) netlink.Link {
	return &netlink.Device{
		LinkAttrs: netlink.LinkAttrs{
			Index:        iface.Index,
			MTU:          iface.MTU,
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr,
			Flags:        iface.Flags,
		},
	}
}

// NewHandle has no netlink equivalent on Windows.
func NewHandle(cfg *HandleConfig) (*netlink.Handle, error) {
	return nil, netlink.ErrNotImplemented
}

// AddrList returns the addresses configured on the given link, filtered by
// address family. It is backed by (*net.Interface).Addrs.
func AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	var iface *net.Interface
	var err error

	if link != nil {
		iface, err = net.InterfaceByIndex(link.Attrs().Index)
		if err != nil {
			return nil, err
		}
	}

	var netAddrs []net.Addr
	if iface != nil {
		netAddrs, err = iface.Addrs()
	} else {
		netAddrs, err = net.InterfaceAddrs()
	}
	if err != nil {
		return nil, err
	}

	addrs := make([]netlink.Addr, 0, len(netAddrs))
	for _, na := range netAddrs {
		ipNet, ok := na.(*net.IPNet)
		if !ok {
			continue
		}
		if !familyMatches(family, ipNet.IP) {
			continue
		}
		addr := netlink.Addr{IPNet: ipNet}
		if iface != nil {
			addr.LinkIndex = iface.Index
		}
		addrs = append(addrs, addr)
	}

	return addrs, nil
}

func familyMatches(family int, ip net.IP) bool {
	switch family {
	case familyV4:
		return ip.To4() != nil
	case familyV6:
		return ip.To4() == nil && ip.To16() != nil
	case familyAll:
		return true
	default:
		return true
	}
}

func ChainList(link netlink.Link, parent uint32) ([]netlink.Chain, error) {
	return nil, netlink.ErrNotImplemented
}

func ClassList(link netlink.Link, parent uint32) ([]netlink.Class, error) {
	return nil, netlink.ErrNotImplemented
}

func ConntrackTableList(table netlink.ConntrackTableType, family netlink.InetFamily) ([]*netlink.ConntrackFlow, error) {
	return nil, netlink.ErrNotImplemented
}

func FilterList(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
	return nil, netlink.ErrNotImplemented
}

func FouList(fam int) ([]netlink.Fou, error) {
	return nil, netlink.ErrNotImplemented
}

func GenlFamilyList() ([]*netlink.GenlFamily, error) {
	return nil, netlink.ErrNotImplemented
}

// LinkByName looks up an interface by name via net.InterfaceByName.
func LinkByName(name string) (netlink.Link, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return linkFromInterface(*iface), nil
}

// LinkByAlias has no portable equivalent on Windows.
func LinkByAlias(alias string) (netlink.Link, error) {
	return nil, netlink.ErrNotImplemented
}

// LinkList enumerates all interfaces via net.Interfaces.
func LinkList() ([]netlink.Link, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	links := make([]netlink.Link, 0, len(ifaces))
	for _, iface := range ifaces {
		links = append(links, linkFromInterface(iface))
	}
	return links, nil
}

func NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return nil, netlink.ErrNotImplemented
}

func NeighProxyList(linkIndex, family int) ([]netlink.Neigh, error) {
	return nil, netlink.ErrNotImplemented
}

func LinkGetProtinfo(link netlink.Link) (netlink.Protinfo, error) {
	return netlink.Protinfo{}, netlink.ErrNotImplemented
}

func QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	return nil, netlink.ErrNotImplemented
}

func RdmaLinkDel(name string) error {
	return netlink.ErrNotImplemented
}

func RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return nil, netlink.ErrNotImplemented
}

func RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return nil, netlink.ErrNotImplemented
}

func RouteListFilteredIter(family int, filter *netlink.Route, filterMask uint64, f func(netlink.Route) (cont bool)) error {
	return netlink.ErrNotImplemented
}

func RuleList(family int) ([]netlink.Rule, error) {
	return nil, netlink.ErrNotImplemented
}

func RuleListFiltered(family int, filter *netlink.Rule, filterMask uint64) ([]netlink.Rule, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketGet(local, remote net.Addr) (*netlink.Socket, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagTCPInfo(family uint8) ([]*netlink.InetDiagTCPInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagTCP(family uint8) ([]*netlink.Socket, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagUDPInfo(family uint8) ([]*netlink.InetDiagUDPInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagUDP(family uint8) ([]*netlink.Socket, error) {
	return nil, netlink.ErrNotImplemented
}

func UnixSocketDiagInfo() ([]*netlink.UnixDiagInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func UnixSocketDiag() ([]*netlink.UnixSocket, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketXDPGetInfo(ino uint32, cookie uint64) (*netlink.XDPDiagInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func SocketDiagXDP() ([]*netlink.XDPDiagInfoResp, error) {
	return nil, netlink.ErrNotImplemented
}

func XfrmPolicyList(family int) ([]netlink.XfrmPolicy, error) {
	return nil, netlink.ErrNotImplemented
}

func XfrmStateList(family int) ([]netlink.XfrmState, error) {
	return nil, netlink.ErrNotImplemented
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ifMaxPhysAddressLength mirrors IF_MAX_PHYS_ADDRESS_LENGTH from ifdef.h.
const ifMaxPhysAddressLength = 32

// MibIpnetRow2 mirrors the MIB_IPNET_ROW2 structure from netioapi.h. It is not
// provided by golang.org/x/sys/windows, so it is defined here. The field layout
// (including the trailing single-byte Flags union followed by the 4-byte
// ReachabilityTime union) matches the C definition.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2
type MibIpnetRow2 struct {
	Address               windows.RawSockaddrInet6 // SOCKADDR_INET union (28 bytes)
	InterfaceIndex        uint32
	InterfaceLuid         uint64
	PhysicalAddress       [ifMaxPhysAddressLength]byte
	PhysicalAddressLength uint32
	State                 uint32 // NL_NEIGHBOR_STATE
	Flags                 uint8  // IsRouter:1 | IsUnreachable:1
	_                     [3]byte
	ReachabilityTime      uint32 // LastReachable / LastUnreachable union
}

var (
	procCreateIpNetEntry2 = modiphlpapi.NewProc("CreateIpNetEntry2")
	procDeleteIpNetEntry2 = modiphlpapi.NewProc("DeleteIpNetEntry2")
)

// CreateIpNetEntry2 adds a neighbor (ARP/ND) entry. It wraps CreateIpNetEntry2
// from netioapi and is the Windows counterpart of netlink.NeighAdd.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipnetentry2
func CreateIpNetEntry2(row *MibIpnetRow2) error {
	if ret, _, _ := procCreateIpNetEntry2.Call(uintptr(unsafe.Pointer(row))); ret != 0 {
		return fmt.Errorf("CreateIpNetEntry2: %w", windows.Errno(ret))
	}
	return nil
}

// DeleteIpNetEntry2 removes a neighbor entry. It is the Windows counterpart of
// netlink.NeighDel.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipnetentry2
func DeleteIpNetEntry2(row *MibIpnetRow2) error {
	if ret, _, _ := procDeleteIpNetEntry2.Call(uintptr(unsafe.Pointer(row))); ret != 0 {
		return fmt.Errorf("DeleteIpNetEntry2: %w", windows.Errno(ret))
	}
	return nil
}

// AddNeighbor adds a static neighbor entry mapping ip to the given hardware
// address on the interface identified by ifaceIndex. It is the Windows
// counterpart of netlink.NeighAdd with a permanent/static ARP entry.
func AddNeighbor(ifaceIndex uint32, ip netip.Addr, hwAddr net.HardwareAddr) error {
	if len(hwAddr) > ifMaxPhysAddressLength {
		return fmt.Errorf("hardware address too long: %d bytes", len(hwAddr))
	}

	var row MibIpnetRow2
	row.InterfaceIndex = ifaceIndex
	if err := setSockaddrInet(&row.Address, ip); err != nil {
		return err
	}
	copy(row.PhysicalAddress[:], hwAddr)
	row.PhysicalAddressLength = uint32(len(hwAddr))

	return CreateIpNetEntry2(&row)
}

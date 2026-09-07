// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procInitializeIpForwardEntry = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2    = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = modiphlpapi.NewProc("DeleteIpForwardEntry2")
)

// InitializeIpForwardEntry initializes a MIB_IPFORWARD_ROW2 with default
// values. It wraps InitializeIpForwardEntry from netioapi.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeipforwardentry
func InitializeIpForwardEntry(row *windows.MibIpForwardRow2) {
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(row)))
}

// CreateIpForwardEntry2 creates a new route entry. It wraps
// CreateIpForwardEntry2 from netioapi and is the Windows counterpart of
// netlink.RouteAdd.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2
func CreateIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	if ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row))); ret != 0 {
		return fmt.Errorf("CreateIpForwardEntry2: %w", windows.Errno(ret))
	}
	return nil
}

// DeleteIpForwardEntry2 removes a route entry. It is the Windows counterpart of
// netlink.RouteDel.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2
func DeleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	if ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row))); ret != 0 {
		return fmt.Errorf("DeleteIpForwardEntry2: %w", windows.Errno(ret))
	}
	return nil
}

// AddRoute creates a route for dst reachable via nextHop on the interface
// identified by ifaceIndex. If nextHop is the zero netip.Addr, an on-link route
// is created (NextHop left unspecified). It is the Windows counterpart of
// netlink.RouteAdd/RouteReplace.
func AddRoute(ifaceIndex uint32, dst netip.Prefix, nextHop netip.Addr) error {
	var row windows.MibIpForwardRow2
	InitializeIpForwardEntry(&row)

	row.InterfaceIndex = ifaceIndex
	row.DestinationPrefix.PrefixLength = uint8(dst.Bits())
	if err := setSockaddrInet((*windows.RawSockaddrInet6)(unsafe.Pointer(&row.DestinationPrefix.Prefix)), dst.Addr()); err != nil {
		return fmt.Errorf("route destination: %w", err)
	}

	if nextHop.IsValid() {
		if err := setSockaddrInet((*windows.RawSockaddrInet6)(unsafe.Pointer(&row.NextHop)), nextHop); err != nil {
			return fmt.Errorf("route next hop: %w", err)
		}
	} else {
		// On-link route: the next-hop family still has to match the destination
		// so the stack accepts the row; the address itself stays unspecified.
		row.NextHop.Family = row.DestinationPrefix.Prefix.Family
	}

	return CreateIpForwardEntry2(&row)
}

// ListRoutes enumerates the system routing table for the given family
// (windows.AF_INET, windows.AF_INET6 or windows.AF_UNSPEC for both). It is a
// read-only helper backed by GetIpForwardTable2 and is the Windows counterpart
// of netlink.RouteList.
func ListRoutes(family uint16) ([]windows.MibIpForwardRow2, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &table); err != nil {
		return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	rows := table.Rows()
	out := make([]windows.MibIpForwardRow2, len(rows))
	copy(out, rows)
	return out, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

// Package netio provides thin, cgo-free Go bindings for the subset of the
// Windows netioapi / iphlpapi (iphlpapi.dll) surface that the Cilium datapath
// needs on Windows. The functions here are the Windows counterparts of the
// Linux netlink address-programming operations (see the Stage 3 porting
// design): they are used to assign IP addresses to interfaces and to resolve
// interface identifiers.
//
// Bindings follow the same no-cgo, lazily-loaded-DLL approach used elsewhere in
// the Windows port (matching the winebpfmap reference implementation).
package netio

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procInitializeUnicastIpAddressEntry = modiphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry     = modiphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procConvertInterfaceIndexToLuid     = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procConvertInterfaceLuidToGuid      = modiphlpapi.NewProc("ConvertInterfaceLuidToGuid")
)

// setSockaddrInet writes addr into a SOCKADDR_INET union (represented by
// windows.RawSockaddrInet6, which is large enough for both families).
func setSockaddrInet(dst *windows.RawSockaddrInet6, addr netip.Addr) error {
	switch {
	case addr.Is4():
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(dst))
		p.Family = windows.AF_INET
		p.Addr = addr.As4()
	case addr.Is6():
		dst.Family = windows.AF_INET6
		dst.Addr = addr.As16()
	default:
		return fmt.Errorf("invalid IP address %q", addr)
	}
	return nil
}

// InitializeUnicastIpAddressEntry initializes a MIB_UNICASTIPADDRESS_ROW with
// default values. It wraps InitializeUnicastIpAddressEntry from netioapi.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeunicastipaddressentry
func InitializeUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) {
	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
}

// CreateUnicastIpAddressEntry adds a new unicast IP address entry, i.e. assigns
// an IP address to an interface. It wraps CreateUnicastIpAddressEntry from
// netioapi. This is the Windows counterpart of netlink.AddrAdd.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry
func CreateUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	if ret, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row))); ret != 0 {
		return fmt.Errorf("CreateUnicastIpAddressEntry: %w", windows.Errno(ret))
	}
	return nil
}

// DeleteUnicastIpAddressEntry removes a unicast IP address entry from an
// interface. It is the Windows counterpart of netlink.AddrDel.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteunicastipaddressentry
func DeleteUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	if ret, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row))); ret != 0 {
		return fmt.Errorf("DeleteUnicastIpAddressEntry: %w", windows.Errno(ret))
	}
	return nil
}

// ConvertInterfaceIndexToLuid resolves a NET_LUID from an interface index.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceindextoluid
func ConvertInterfaceIndexToLuid(index uint32) (luid uint64, err error) {
	if ret, _, _ := procConvertInterfaceIndexToLuid.Call(
		uintptr(index),
		uintptr(unsafe.Pointer(&luid)),
	); ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceIndexToLuid: %w", windows.Errno(ret))
	}
	return luid, nil
}

// ConvertInterfaceLuidToGuid resolves the interface GUID from its NET_LUID.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoguid
func ConvertInterfaceLuidToGuid(luid uint64) (guid windows.GUID, err error) {
	if ret, _, _ := procConvertInterfaceLuidToGuid.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&guid)),
	); ret != 0 {
		return windows.GUID{}, fmt.Errorf("ConvertInterfaceLuidToGuid: %w", windows.Errno(ret))
	}
	return guid, nil
}

// AssignUnicastIP assigns the given IP prefix to the interface identified by
// ifaceIndex. It is a convenience wrapper around
// InitializeUnicastIpAddressEntry + CreateUnicastIpAddressEntry and is the
// Windows counterpart of netlink.AddrAdd/AddrReplace.
func AssignUnicastIP(ifaceIndex uint32, prefix netip.Prefix) error {
	var row windows.MibUnicastIpAddressRow
	InitializeUnicastIpAddressEntry(&row)

	row.InterfaceIndex = ifaceIndex
	row.OnLinkPrefixLength = uint8(prefix.Bits())
	if err := setSockaddrInet(&row.Address, prefix.Addr()); err != nil {
		return err
	}

	return CreateUnicastIpAddressEntry(&row)
}

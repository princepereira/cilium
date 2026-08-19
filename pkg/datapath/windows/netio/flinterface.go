// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Forwarding-Layer virtual interface APIs (MIB_FL_VIRTUAL_INTERFACE_ROW and
// the Create/Get/Delete/Initialize entry points) are reserved, undocumented
// netioapi functions used by the Windows networking stack to create per-pod
// forwarding-layer virtual interfaces. Their row structure has no public
// definition, so these wrappers operate on caller-owned row memory (an
// unsafe.Pointer to the MIB_FL_VIRTUAL_INTERFACE_ROW the caller populates) and
// are bound best-effort: on hosts where an export is unavailable the wrapper
// returns an error instead of panicking.

var (
	procInitializeFlVirtualInterfaceEntry = modiphlpapi.NewProc("InitializeFlVirtualInterfaceEntry")
	procCreateFlVirtualInterface          = modiphlpapi.NewProc("CreateFlVirtualInterface")
	procGetFlVirtualInterface             = modiphlpapi.NewProc("GetFlVirtualInterface")
	procDeleteFlVirtualInterface          = modiphlpapi.NewProc("DeleteFlVirtualInterface")
)

// InitializeFlVirtualInterfaceEntry initializes a MIB_FL_VIRTUAL_INTERFACE_ROW
// (pointed to by row) with default values.
func InitializeFlVirtualInterfaceEntry(row unsafe.Pointer) error {
	if err := procInitializeFlVirtualInterfaceEntry.Find(); err != nil {
		return fmt.Errorf("InitializeFlVirtualInterfaceEntry unavailable: %w", err)
	}
	procInitializeFlVirtualInterfaceEntry.Call(uintptr(row))
	return nil
}

// CreateFlVirtualInterface creates a forwarding-layer virtual interface from the
// MIB_FL_VIRTUAL_INTERFACE_ROW pointed to by row. It is used to create a pod's
// virtual interface on Windows.
func CreateFlVirtualInterface(row unsafe.Pointer) error {
	if err := procCreateFlVirtualInterface.Find(); err != nil {
		return fmt.Errorf("CreateFlVirtualInterface unavailable: %w", err)
	}
	if ret, _, _ := procCreateFlVirtualInterface.Call(uintptr(row)); ret != 0 {
		return fmt.Errorf("CreateFlVirtualInterface: %w", windows.Errno(ret))
	}
	return nil
}

// GetFlVirtualInterface reads back a forwarding-layer virtual interface into the
// MIB_FL_VIRTUAL_INTERFACE_ROW pointed to by row (which must be pre-populated
// with the lookup key, e.g. the LUID).
func GetFlVirtualInterface(row unsafe.Pointer) error {
	if err := procGetFlVirtualInterface.Find(); err != nil {
		return fmt.Errorf("GetFlVirtualInterface unavailable: %w", err)
	}
	if ret, _, _ := procGetFlVirtualInterface.Call(uintptr(row)); ret != 0 {
		return fmt.Errorf("GetFlVirtualInterface: %w", windows.Errno(ret))
	}
	return nil
}

// DeleteFlVirtualInterface deletes a forwarding-layer virtual interface
// identified by the MIB_FL_VIRTUAL_INTERFACE_ROW pointed to by row.
func DeleteFlVirtualInterface(row unsafe.Pointer) error {
	if err := procDeleteFlVirtualInterface.Find(); err != nil {
		return fmt.Errorf("DeleteFlVirtualInterface unavailable: %w", err)
	}
	if ret, _, _ := procDeleteFlVirtualInterface.Call(uintptr(row)); ret != 0 {
		return fmt.Errorf("DeleteFlVirtualInterface: %w", windows.Errno(ret))
	}
	return nil
}

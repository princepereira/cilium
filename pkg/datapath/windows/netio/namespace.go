// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CompartmentID identifies a Windows network compartment (NET_IF_COMPARTMENT_ID).
// A network compartment is the Windows equivalent of a Linux network namespace.
type CompartmentID uint32

const (
	// UnspecifiedCompartmentID (NET_IF_COMPARTMENT_ID_UNSPECIFIED).
	UnspecifiedCompartmentID CompartmentID = 0
	// PrimaryCompartmentID (NET_IF_COMPARTMENT_ID_PRIMARY) is the host's default
	// compartment.
	PrimaryCompartmentID CompartmentID = 1
)

var (
	procSetCurrentThreadCompartmentId    = modiphlpapi.NewProc("SetCurrentThreadCompartmentId")
	procGetCurrentThreadCompartmentId    = modiphlpapi.NewProc("GetCurrentThreadCompartmentId")
	procSetCurrentThreadCompartmentScope = modiphlpapi.NewProc("SetCurrentThreadCompartmentScope")
	procCreateCompartment                = modiphlpapi.NewProc("CreateCompartment")
	procDeleteCompartment                = modiphlpapi.NewProc("DeleteCompartment")
)

// GetCurrentThreadCompartmentId returns the compartment the current OS thread is
// bound to. Callers should runtime.LockOSThread around compartment-scoped work.
//
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getcurrentthreadcompartmentid
func GetCurrentThreadCompartmentId() CompartmentID {
	ret, _, _ := procGetCurrentThreadCompartmentId.Call()
	return CompartmentID(ret)
}

// SetCurrentThreadCompartmentId binds the current OS thread to the given
// compartment. It is the Windows counterpart of entering a network namespace
// (netns.Set). Callers must runtime.LockOSThread first and restore the previous
// compartment when done.
//
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-setcurrentthreadcompartmentid
func SetCurrentThreadCompartmentId(id CompartmentID) error {
	if ret, _, _ := procSetCurrentThreadCompartmentId.Call(uintptr(id)); ret != 0 {
		return fmt.Errorf("SetCurrentThreadCompartmentId(%d): %w", id, windows.Errno(ret))
	}
	return nil
}

// SetCurrentThreadCompartmentScope widens or resets the compartment scope of the
// current thread.
//
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-setcurrentthreadcompartmentscope
func SetCurrentThreadCompartmentScope(scope uint32) error {
	if ret, _, _ := procSetCurrentThreadCompartmentScope.Call(uintptr(scope)); ret != 0 {
		return fmt.Errorf("SetCurrentThreadCompartmentScope(%d): %w", scope, windows.Errno(ret))
	}
	return nil
}

// CreateCompartment creates a new network compartment and returns its ID. It is
// the Windows counterpart of creating a network namespace (netns.New).
//
// Note: CreateCompartment/DeleteCompartment are reserved netioapi entry points.
// They are bound best-effort; on hosts where they are not exported the call
// returns an error rather than panicking.
func CreateCompartment() (CompartmentID, error) {
	if err := procCreateCompartment.Find(); err != nil {
		return UnspecifiedCompartmentID, fmt.Errorf("CreateCompartment unavailable: %w", err)
	}
	var id CompartmentID
	if ret, _, _ := procCreateCompartment.Call(uintptr(unsafe.Pointer(&id))); ret != 0 {
		return UnspecifiedCompartmentID, fmt.Errorf("CreateCompartment: %w", windows.Errno(ret))
	}
	return id, nil
}

// DeleteCompartment removes a previously created network compartment. It is the
// Windows counterpart of deleting a network namespace.
func DeleteCompartment(id CompartmentID) error {
	if err := procDeleteCompartment.Find(); err != nil {
		return fmt.Errorf("DeleteCompartment unavailable: %w", err)
	}
	if ret, _, _ := procDeleteCompartment.Call(uintptr(id)); ret != 0 {
		return fmt.Errorf("DeleteCompartment(%d): %w", id, windows.Errno(ret))
	}
	return nil
}

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenJobObject = modkernel32.NewProc("OpenJobObjectW")
)

// Job object access rights (winnt.h).
const (
	JOB_OBJECT_QUERY          = 0x0004
	JOB_OBJECT_ALL_ACCESS     = 0x1F001F
	JOB_OBJECT_TERMINATE      = 0x0008
	JOB_OBJECT_SET_ATTRIBUTES = 0x0002
)

// OpenJobObject opens an existing job object by name. It is the practical,
// documented counterpart of the NtOpenJobObject call the Windows agent uses to
// obtain a handle to a container's job object.
//
// https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-openjobobjectw
func OpenJobObject(desiredAccess uint32, inheritHandle bool, name string) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var inherit uintptr
	if inheritHandle {
		inherit = 1
	}
	ret, _, callErr := procOpenJobObject.Call(
		uintptr(desiredAccess),
		inherit,
		uintptr(unsafe.Pointer(namePtr)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenJobObject(%q): %w", name, callErr)
	}
	return windows.Handle(ret), nil
}

var (
	modcontainer = windows.NewLazyDLL("container.dll")

	procWcAddRuntimeVirtualKeysToContainer = modcontainer.NewProc("WcAddRuntimeVirtualKeysToContainer")
)

// AddRuntimeVirtualKeysToContainer injects runtime virtual TCPIP registry keys
// into a Windows Server container via container.dll. It is only available inside
// the container runtime environment; on hosts where container.dll or the export
// is unavailable it returns an error.
//
// containerFn is the container-callback context pointer passed through to the
// API; callers own its lifetime.
func AddRuntimeVirtualKeysToContainer(containerFn uintptr) error {
	if err := procWcAddRuntimeVirtualKeysToContainer.Find(); err != nil {
		return fmt.Errorf("WcAddRuntimeVirtualKeysToContainer unavailable: %w", err)
	}
	if ret, _, callErr := procWcAddRuntimeVirtualKeysToContainer.Call(containerFn); ret != 0 {
		return fmt.Errorf("WcAddRuntimeVirtualKeysToContainer: %w (status 0x%x)", callErr, ret)
	}
	return nil
}

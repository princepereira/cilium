// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wsaVersion22 is MAKEWORD(2, 2).
const wsaVersion22 = 0x0202

// WSAStartup initializes Winsock for the process (version 2.2). It is the
// counterpart of the WSAStartup call the Windows agent issues at start-up. The
// Go standard library initializes Winsock on its own, so this is only needed
// when calling Winsock APIs directly.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
func WSAStartup() error {
	var data windows.WSAData
	if err := windows.WSAStartup(wsaVersion22, &data); err != nil {
		return fmt.Errorf("WSAStartup: %w", err)
	}
	return nil
}

// WSACleanup tears down the process's Winsock usage. Each successful WSAStartup
// must be balanced by a WSACleanup.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsacleanup
func WSACleanup() error {
	if err := windows.WSACleanup(); err != nil {
		return fmt.Errorf("WSACleanup: %w", err)
	}
	return nil
}

const (
	// infiniteTimeout is INFINITE for wait APIs.
	infiniteTimeout = 0xFFFFFFFF
	// wtExecuteDefault is WT_EXECUTEDEFAULT.
	wtExecuteDefault = 0x0
)

var (
	procRegisterWaitForSingleObject = modkernel32.NewProc("RegisterWaitForSingleObject")
	procUnregisterWaitEx            = modkernel32.NewProc("UnregisterWaitEx")
)

// RegistryWatcher watches a registry key for changes and invokes a callback on
// every change. It combines RegNotifyChangeKeyValue (to arm a change event) with
// RegisterWaitForSingleObject (to fire a callback when the event signals),
// mirroring the node-config watch in the Windows agent.
type RegistryWatcher struct {
	key        windows.Handle
	event      windows.Handle
	waitHandle windows.Handle
	callback   uintptr
	watchTree  bool
	filter     uint32
	onChange   func()
}

// WatchRegistryKey starts watching key for the change classes selected by filter
// (a combination of windows.REG_NOTIFY_CHANGE_* flags). onChange is invoked on a
// system worker thread for each change until Close is called; it must be
// non-blocking and concurrency-safe.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue
func WatchRegistryKey(key windows.Handle, watchSubtree bool, filter uint32, onChange func()) (*RegistryWatcher, error) {
	if onChange == nil {
		return nil, fmt.Errorf("onChange must not be nil")
	}

	// Auto-reset, initially non-signaled event.
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}

	w := &RegistryWatcher{
		key:       key,
		event:     event,
		watchTree: watchSubtree,
		filter:    filter,
		onChange:  onChange,
	}

	w.callback = windows.NewCallback(func(_ uintptr, _ uint32) uintptr {
		// RegNotifyChangeKeyValue is one-shot; re-arm before delivering so that
		// changes racing with the callback are not missed.
		_ = windows.RegNotifyChangeKeyValue(w.key, w.watchTree, w.filter, w.event, true)
		w.onChange()
		return 0
	})

	if err := windows.RegNotifyChangeKeyValue(key, watchSubtree, filter, event, true); err != nil {
		windows.CloseHandle(event)
		return nil, fmt.Errorf("RegNotifyChangeKeyValue: %w", err)
	}

	ret, _, callErr := procRegisterWaitForSingleObject.Call(
		uintptr(unsafe.Pointer(&w.waitHandle)),
		uintptr(event),
		w.callback,
		0,
		infiniteTimeout,
		wtExecuteDefault,
	)
	if ret == 0 {
		windows.CloseHandle(event)
		return nil, fmt.Errorf("RegisterWaitForSingleObject: %w", callErr)
	}

	return w, nil
}

// Close stops the registry watch and releases its resources. It blocks until any
// in-flight callback has completed.
func (w *RegistryWatcher) Close() error {
	if w == nil {
		return nil
	}
	if w.waitHandle != 0 {
		// UnregisterWaitEx with INVALID_HANDLE_VALUE waits for pending callbacks.
		procUnregisterWaitEx.Call(uintptr(w.waitHandle), uintptr(windows.InvalidHandle))
		w.waitHandle = 0
	}
	if w.event != 0 {
		windows.CloseHandle(w.event)
		w.event = 0
	}
	return nil
}

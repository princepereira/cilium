// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"errors"
	"net"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCurrentThreadCompartment(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig := GetCurrentThreadCompartmentId()
	if orig == UnspecifiedCompartmentID {
		t.Fatalf("GetCurrentThreadCompartmentId returned unspecified")
	}

	// Re-binding to the current compartment must succeed and be a no-op.
	// Binding a thread to a compartment requires elevation; on a non-admin host
	// the API returns ACCESS_DENIED, which still proves the binding invoked the
	// real entry point.
	if err := SetCurrentThreadCompartmentId(orig); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Skipf("SetCurrentThreadCompartmentId requires elevation: %v", err)
		}
		t.Fatalf("SetCurrentThreadCompartmentId(%d): %v", orig, err)
	}
	if got := GetCurrentThreadCompartmentId(); got != orig {
		t.Errorf("compartment id = %d, want %d", got, orig)
	}
}

func TestPortReservationRuntime(t *testing.T) {
	sock, err := windows.WSASocket(windows.AF_INET, windows.SOCK_DGRAM, windows.IPPROTO_UDP, nil, 0, windows.WSA_FLAG_OVERLAPPED)
	if err != nil {
		t.Fatalf("WSASocket: %v", err)
	}
	defer windows.Closesocket(sock)

	res, err := AcquirePortReservation(sock, 0, 1)
	if err != nil {
		// Port reservation can be unsupported for the socket/host (e.g. in some
		// container or non-elevated contexts); the binding still ran correctly.
		if errors.Is(err, windows.WSAEOPNOTSUPP) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Skipf("port reservation unsupported in this environment: %v", err)
		}
		t.Fatalf("AcquirePortReservation: %v", err)
	}
	if res.NumberOfPorts != 1 || res.StartPort == 0 {
		t.Errorf("unexpected reservation: %+v", res)
	}

	if err := ReleasePortReservation(sock, res); err != nil {
		t.Errorf("ReleasePortReservation: %v", err)
	}
}

func TestGetInterfaceDnsSettings(t *testing.T) {
	if err := procGetInterfaceDnsSettings.Find(); err != nil {
		t.Skipf("GetInterfaceDnsSettings unavailable: %v", err)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}

	var ok int
	for _, iface := range ifaces {
		luid, err := ConvertInterfaceIndexToLuid(uint32(iface.Index))
		if err != nil {
			continue
		}
		guid, err := ConvertInterfaceLuidToGuid(luid)
		if err != nil {
			continue
		}
		settings, err := GetInterfaceDnsSettings(guid, DnsSettingNameServer|DnsSettingDomain)
		if err != nil {
			t.Logf("interface %s: GetInterfaceDnsSettings: %v", iface.Name, err)
			continue
		}
		FreeInterfaceDnsSettings(settings)
		ok++
	}

	if ok == 0 {
		t.Fatal("GetInterfaceDnsSettings did not succeed for any interface")
	}
}

func TestWSAStartupCleanup(t *testing.T) {
	if err := WSAStartup(); err != nil {
		t.Fatalf("WSAStartup: %v", err)
	}
	if err := WSACleanup(); err != nil {
		t.Errorf("WSACleanup: %v", err)
	}
}

func TestWatchRegistryKeySetup(t *testing.T) {
	w, err := WatchRegistryKey(windows.HKEY_CURRENT_USER, false, windows.REG_NOTIFY_CHANGE_LAST_SET, func() {})
	if err != nil {
		t.Fatalf("WatchRegistryKey: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNamespaceProcsResolve(t *testing.T) {
	// Documented, always-present entry points.
	required := map[string]*windows.LazyProc{
		"SetCurrentThreadCompartmentId": procSetCurrentThreadCompartmentId,
		"GetCurrentThreadCompartmentId": procGetCurrentThreadCompartmentId,
		"OpenJobObjectW":                procOpenJobObject,
		"RegisterWaitForSingleObject":   procRegisterWaitForSingleObject,
		"UnregisterWaitEx":              procUnregisterWaitEx,
	}
	for name, proc := range required {
		if err := proc.Find(); err != nil {
			t.Errorf("export %q not found: %v", name, err)
		}
	}
}

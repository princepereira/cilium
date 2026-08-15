// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestProcsResolve ensures every netioapi entry point this package binds is
// actually exported by iphlpapi.dll on the host.
func TestProcsResolve(t *testing.T) {
	procs := map[string]*windows.LazyProc{
		"InitializeUnicastIpAddressEntry": procInitializeUnicastIpAddressEntry,
		"CreateUnicastIpAddressEntry":     procCreateUnicastIpAddressEntry,
		"DeleteUnicastIpAddressEntry":     procDeleteUnicastIpAddressEntry,
		"ConvertInterfaceIndexToLuid":     procConvertInterfaceIndexToLuid,
		"ConvertInterfaceLuidToGuid":      procConvertInterfaceLuidToGuid,
		"InitializeIpForwardEntry":        procInitializeIpForwardEntry,
		"CreateIpForwardEntry2":           procCreateIpForwardEntry2,
		"DeleteIpForwardEntry2":           procDeleteIpForwardEntry2,
		"CreateIpNetEntry2":               procCreateIpNetEntry2,
		"DeleteIpNetEntry2":               procDeleteIpNetEntry2,
	}
	for name, proc := range procs {
		if err := proc.Find(); err != nil {
			t.Errorf("iphlpapi.dll export %q not found: %v", name, err)
		}
	}
}

// TestMibIpnetRow2Size guards the hand-defined MIB_IPNET_ROW2 layout against
// accidental drift.
func TestMibIpnetRow2Size(t *testing.T) {
	const want = 88
	if got := unsafe.Sizeof(MibIpnetRow2{}); got != want {
		t.Errorf("sizeof(MibIpnetRow2) = %d, want %d", got, want)
	}
}

// TestListRoutes exercises the read-only route-table enumeration.
func TestListRoutes(t *testing.T) {
	routes, err := ListRoutes(windows.AF_UNSPEC)
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("ListRoutes returned no routes")
	}
	for _, r := range routes {
		if r.InterfaceIndex == 0 {
			t.Errorf("route with zero interface index: %+v", r)
		}
	}
}

// TestSubscribeUnicastAddressChange registers a subscription with an initial
// notification and verifies the callback fires, then unsubscribes. This is a
// read-only exercise of NotifyUnicastIpAddressChange / CancelMibChangeNotify2.
func TestSubscribeUnicastAddressChange(t *testing.T) {
	got := make(chan NotificationType, 8)
	sub, err := SubscribeUnicastAddressChange(windows.AF_UNSPEC, true, func(_ *windows.MibUnicastIpAddressRow, typ NotificationType) {
		select {
		case got <- typ:
		default:
		}
	})
	if err != nil {
		t.Fatalf("SubscribeUnicastAddressChange: %v", err)
	}
	defer func() {
		if err := sub.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	select {
	case typ := <-got:
		if typ != NotificationInitial {
			t.Errorf("first notification = %v, want initial", typ)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial address-change notification")
	}
}

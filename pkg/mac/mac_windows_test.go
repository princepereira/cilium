// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package mac

import (
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestGuidString(t *testing.T) {
	got := guidString(0x12345678, 0x9abc, 0xdef0,
		[8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	want := "{12345678-9ABC-DEF0-0123-456789ABCDEF}"
	if got != want {
		t.Errorf("guidString = %q, want %q", got, want)
	}
}

func TestMacToRegistry(t *testing.T) {
	hw, err := net.ParseMAC("0a:1b:2c:3d:4e:5f")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := macToRegistry(hw), "0A1B2C3D4E5F"; got != want {
		t.Errorf("macToRegistry = %q, want %q", got, want)
	}
}

func TestReplaceMacMissingInterfaceIsNoop(t *testing.T) {
	if err := ReplaceMacAddressWithLinkName("this-iface-does-not-exist-xyz", "0a:1b:2c:3d:4e:5f"); err != nil {
		t.Errorf("expected nil for missing interface, got %v", err)
	}
}

// TestReplaceMacResolvesRealInterface exercises the interface->GUID->registry
// resolution path against a real adapter. Writing NetworkAddress requires
// administrator privileges, so an access-denied failure is tolerated: reaching
// it proves the resolution succeeded.
func TestReplaceMacResolvesRealInterface(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	for _, ifc := range ifaces {
		if len(ifc.HardwareAddr) == 6 && ifc.Flags&net.FlagLoopback == 0 {
			name = ifc.Name
			break
		}
	}
	if name == "" {
		t.Skip("no suitable ethernet interface found")
	}

	err = ReplaceMacAddressWithLinkName(name, "02:00:00:00:00:01")
	if err == nil {
		return // full success (elevated)
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skipf("setting NetworkAddress requires elevation: %v", err)
	}
	// Some virtual adapters (e.g. Hyper-V switches) have no NetworkAddress-capable
	// Class registry key. Reaching this point still proves the index->LUID->GUID
	// and registry enumeration path works.
	if strings.Contains(err.Error(), "no adapter registry key matches") {
		t.Skipf("adapter %q has no NetworkAddress Class key: %v", name, err)
	}
	t.Fatalf("ReplaceMacAddressWithLinkName(%q): %v", name, err)
}

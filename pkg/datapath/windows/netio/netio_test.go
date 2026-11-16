// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"net"
	"testing"
)

// TestConvertInterfaceIndexToLuidToGuid exercises the read-only netioapi
// bindings against a real interface on the host. It verifies the LUID/GUID
// resolution chain (ConvertInterfaceIndexToLuid -> ConvertInterfaceLuidToGuid)
// works end-to-end without mutating system state.
func TestConvertInterfaceIndexToLuidToGuid(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	if len(ifaces) == 0 {
		t.Skip("no interfaces available")
	}

	var resolved int
	for _, iface := range ifaces {
		luid, err := ConvertInterfaceIndexToLuid(uint32(iface.Index))
		if err != nil {
			t.Logf("index %d (%s): ConvertInterfaceIndexToLuid: %v", iface.Index, iface.Name, err)
			continue
		}
		if _, err := ConvertInterfaceLuidToGuid(luid); err != nil {
			t.Errorf("index %d (%s): ConvertInterfaceLuidToGuid: %v", iface.Index, iface.Name, err)
			continue
		}
		resolved++
	}

	if resolved == 0 {
		t.Fatalf("failed to resolve LUID/GUID for any of %d interfaces", len(ifaces))
	}
}

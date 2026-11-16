// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netns

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/cilium/cilium/pkg/datapath/windows/netio"
)

func TestCurrentAndCookie(t *testing.T) {
	ns, err := Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if ns.FD() != int(netio.PrimaryCompartmentID) && ns.FD() <= 0 {
		t.Errorf("unexpected compartment FD %d", ns.FD())
	}

	cookie, err := GetNetNSCookie()
	if err != nil {
		t.Fatalf("GetNetNSCookie: %v", err)
	}
	if cookie != uint64(ns.FD()) {
		t.Errorf("cookie %d != current compartment %d", cookie, ns.FD())
	}
}

func TestOpenPinnedParsesCompartmentID(t *testing.T) {
	tests := map[string]int{
		"1":                   1,
		"42":                  42,
		`\\.\compartments\7`:  7,
		"/var/run/compart/13": 13,
	}
	for in, want := range tests {
		ns, err := OpenPinned(in)
		if err != nil {
			t.Errorf("OpenPinned(%q): %v", in, err)
			continue
		}
		if ns.FD() != want {
			t.Errorf("OpenPinned(%q).FD() = %d, want %d", in, ns.FD(), want)
		}
	}

	if _, err := OpenPinned("not-a-number"); err == nil {
		t.Error("OpenPinned(non-numeric) expected error, got nil")
	}
}

func TestDoRunsCallback(t *testing.T) {
	ns, err := Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	ran := false
	err = ns.Do(func() error {
		ran = true
		return nil
	})
	// Binding a thread to a compartment requires elevation; without it the API
	// returns ACCESS_DENIED before the callback runs. Either way the binding was
	// exercised.
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Skipf("Do requires elevation to set compartment: %v", err)
		}
		t.Fatalf("Do: %v", err)
	}
	if !ran {
		t.Error("Do did not run the callback")
	}
}

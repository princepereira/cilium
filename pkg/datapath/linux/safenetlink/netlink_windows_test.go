// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package safenetlink

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// TestLinkListWindows verifies the Windows LinkList backend returns real
// interfaces sourced from the Go standard library net package.
func TestLinkListWindows(t *testing.T) {
	links, err := LinkList()
	if err != nil {
		t.Fatalf("LinkList: %v", err)
	}
	if len(links) == 0 {
		t.Fatal("LinkList returned no interfaces")
	}

	for _, l := range links {
		attrs := l.Attrs()
		if attrs.Name == "" {
			t.Errorf("interface with index %d has empty name", attrs.Index)
		}

		// A named link must be resolvable by name and report a matching index.
		byName, err := LinkByName(attrs.Name)
		if err != nil {
			t.Errorf("LinkByName(%q): %v", attrs.Name, err)
			continue
		}
		if got := byName.Attrs().Index; got != attrs.Index {
			t.Errorf("LinkByName(%q) index = %d, want %d", attrs.Name, got, attrs.Index)
		}
	}
}

// TestAddrListWindows verifies AddrList returns addresses for a link and that
// family filtering behaves consistently.
func TestAddrListWindows(t *testing.T) {
	links, err := LinkList()
	if err != nil {
		t.Fatalf("LinkList: %v", err)
	}

	var total int
	for _, l := range links {
		all, err := AddrList(l, familyAll)
		if err != nil {
			t.Fatalf("AddrList(all): %v", err)
		}
		v4, err := AddrList(l, familyV4)
		if err != nil {
			t.Fatalf("AddrList(v4): %v", err)
		}
		v6, err := AddrList(l, familyV6)
		if err != nil {
			t.Fatalf("AddrList(v6): %v", err)
		}
		if len(v4)+len(v6) != len(all) {
			t.Errorf("link %s: v4(%d)+v6(%d) != all(%d)", l.Attrs().Name, len(v4), len(v6), len(all))
		}
		total += len(all)
	}

	if total == 0 {
		t.Fatal("no addresses found on any interface")
	}
}

// TestUnimplementedReturnsErrNotImplemented ensures the un-ported mutating
// helpers keep returning netlink.ErrNotImplemented on Windows.
func TestUnimplementedReturnsErrNotImplemented(t *testing.T) {
	if _, err := RouteList(nil, familyAll); err != netlink.ErrNotImplemented {
		t.Errorf("RouteList err = %v, want ErrNotImplemented", err)
	}
	if _, err := NeighList(0, familyAll); err != netlink.ErrNotImplemented {
		t.Errorf("NeighList err = %v, want ErrNotImplemented", err)
	}
}

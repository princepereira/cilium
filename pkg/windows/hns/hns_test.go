// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hns

import (
	"net/netip"
	"testing"
)

func TestRemoteNodeRouteValid(t *testing.T) {
	tests := []struct {
		name  string
		route RemoteNodeRoute
		want  bool
	}{
		{
			name: "valid ipv4",
			route: RemoteNodeRoute{
				DestinationPrefix: netip.MustParsePrefix("10.0.1.0/24"),
				ProviderAddress:   netip.MustParseAddr("192.168.0.5"),
				IsolationID:       4096,
			},
			want: true,
		},
		{
			name: "missing provider address",
			route: RemoteNodeRoute{
				DestinationPrefix: netip.MustParsePrefix("10.0.1.0/24"),
			},
			want: false,
		},
		{
			name: "missing destination prefix",
			route: RemoteNodeRoute{
				ProviderAddress: netip.MustParseAddr("192.168.0.5"),
			},
			want: false,
		},
		{
			name:  "zero value",
			route: RemoteNodeRoute{},
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.route.Valid(); got != tt.want {
				t.Fatalf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewManagerNonNil(t *testing.T) {
	// New must always return a usable Manager (never nil), regardless of
	// platform / HCN availability, so callers can invoke it unconditionally.
	if m := New(nil); m == nil {
		t.Fatal("New returned nil Manager")
	}
}

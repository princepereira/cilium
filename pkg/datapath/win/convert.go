// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package win

import (
	"net/netip"

	"github.com/princepereira/cncshim/pkg/cncapi"
)

// IPv4ToAddr converts a 4-byte IPv4 to netip.Addr.
func IPv4ToAddr(ip [4]byte) netip.Addr {
	return netip.AddrFrom4(ip)
}

// IPv6ToAddr converts a 16-byte IPv6 to netip.Addr.
func IPv6ToAddr(ip [16]byte) netip.Addr {
	return netip.AddrFrom16(ip)
}

// MACToABI converts a 6-byte MAC address to cncapi.MACAddress.
func MACToABI(mac [6]byte) cncapi.MACAddress {
	return cncapi.MACAddress(mac)
}

// DirectionToCNC converts cilium policy direction to cncapi.Direction.
func DirectionToCNC(isIngress bool) cncapi.Direction {
	if isIngress {
		return cncapi.DirectionIngress
	}
	return cncapi.DirectionEgress
}

// PermissionToCNC converts cilium allow/deny to cncapi.Permission.
func PermissionToCNC(isDeny bool) cncapi.Permission {
	if isDeny {
		return cncapi.PermissionDeny
	}
	return cncapi.PermissionAllow
}

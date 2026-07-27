// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package node

import (
	"fmt"
	"net"
	"sort"

	"github.com/cilium/cilium/pkg/ip"
)

const (
	familyV4 = 4
	familyV6 = 6
)

// firstGlobalAddr enumerates the host's network interfaces using the standard
// library (which is portable across platforms, including Windows) and returns
// the first suitable global address for the requested family.
//
// Public IPs are preferred over private ones. When intf is defined, only IPs
// belonging to that interface are considered; if no suitable address is found
// there, all interfaces are considered. If preferredIP is present in the
// candidate list it is returned irrespective of sort order.
func firstGlobalAddr(intf string, preferredIP net.IP, family int) (net.IP, error) {
	ipsToExclude := GetExcludedIPs()

	// scoped=true first restricts the search to intf (if provided); on failure
	// we retry with scoped=false across all interfaces.
	find := func(scoped bool) (net.IP, error) {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, err
		}

		ipsPublic := []net.IP{}
		ipsPrivate := []net.IP{}
		hasPreferred := false

		for _, iface := range ifaces {
			if scoped && intf != "" && intf != "undefined" && iface.Name != intf {
				continue
			}
			if iface.Flags&net.FlagUp == 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, a := range addrs {
				var ipAddr net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ipAddr = v.IP
				case *net.IPAddr:
					ipAddr = v.IP
				default:
					continue
				}

				if ipAddr.IsLoopback() || ipAddr.IsLinkLocalUnicast() || ipAddr.IsLinkLocalMulticast() {
					continue
				}

				if family == familyV4 {
					if ipAddr.To4() == nil {
						continue
					}
					ipAddr = ipAddr.To4()
				} else {
					if ipAddr.To4() != nil {
						continue
					}
				}

				if ip.ListContainsIP(ipsToExclude, ipAddr) {
					continue
				}

				isPreferredIP := ipAddr.Equal(preferredIP)
				if isPreferredIP {
					hasPreferred = true
				}

				if ip.IsPublicAddr(ipAddr) {
					ipsPublic = append(ipsPublic, ipAddr)
				} else {
					ipsPrivate = append(ipsPrivate, ipAddr)
				}
			}
		}

		if len(ipsPublic) != 0 {
			if hasPreferred && ip.IsPublicAddr(preferredIP) {
				return preferredIP, nil
			}
			sort.SliceStable(ipsPublic, func(i, j int) bool {
				return ipsPublic[i].String() < ipsPublic[j].String()
			})
			return ipsPublic[0], nil
		}

		if len(ipsPrivate) != 0 {
			if hasPreferred && !ip.IsPublicAddr(preferredIP) {
				return preferredIP, nil
			}
			sort.SliceStable(ipsPrivate, func(i, j int) bool {
				return ipsPrivate[i].String() < ipsPrivate[j].String()
			})
			return ipsPrivate[0], nil
		}

		return nil, fmt.Errorf("no address found")
	}

	if intf != "" && intf != "undefined" {
		if addr, err := find(true); err == nil {
			return addr, nil
		}
	}
	return find(false)
}

// FirstGlobalV4Addr returns the first IPv4 global IP of an interface. See the
// Linux implementation for the full contract; on non-Linux platforms address
// discovery is performed via the standard net package.
func FirstGlobalV4Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, familyV4)
}

// FirstGlobalV6Addr returns the first IPv6 global IP of an interface, see
// FirstGlobalV4Addr for more details.
func FirstGlobalV6Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return firstGlobalAddr(intf, preferredIP, familyV6)
}

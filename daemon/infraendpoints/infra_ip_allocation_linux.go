// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package infraendpoints

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

func (r *infraIPAllocator) waitForENI(ctx context.Context, macAddr string) error {
	bo := wait.Backoff{
		Duration: 250 * time.Millisecond,
		Factor:   2,
		Jitter:   0.2,
		Steps:    5,
	}

	findENIByMAC := func(ctx context.Context) (bool, error) {
		links, err := safenetlink.LinkList()
		if err != nil {
			return false, fmt.Errorf("unable to list interfaces: %w", err)
		}

		for _, l := range links {
			// filter out slave devices
			if l.Attrs().RawFlags&unix.IFF_SLAVE != 0 {
				continue
			}
			if l.Attrs().HardwareAddr.String() == macAddr {
				return true, nil
			}
		}
		return false, nil
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, findENIByMAC)
}

// removeOldRouterState will try to ensure that the only IP assigned to the
// `cilium_host` interface is the given restored IP. If the given IP is nil,
// then it attempts to clear all IPs from the interface.
func (r *infraIPAllocator) removeOldRouterState(ipv6 bool, restoredIP net.IP) error {
	l, err := safenetlink.LinkByName(defaults.HostDevice)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		// There's no old state remove as the host device doesn't exist.
		// This is always the case when the agent is started for the first time.
		return nil
	}
	if err != nil {
		return resiliency.Retryable(err)
	}

	family := netlink.FAMILY_V4
	if ipv6 {
		family = netlink.FAMILY_V6
	}
	addrs, err := safenetlink.AddrList(l, family)
	if err != nil {
		return resiliency.Retryable(err)
	}

	isRestoredIP := func(a netlink.Addr) bool {
		return restoredIP != nil && restoredIP.Equal(a.IP)
	}
	if len(addrs) == 0 || (len(addrs) == 1 && isRestoredIP(addrs[0])) {
		return nil // nothing to clean up
	}

	r.logger.Info("More than one stale router IP was found on the cilium_host device after restoration, cleaning up old router IPs.")

	for _, a := range addrs {
		if isRestoredIP(a) {
			continue
		}
		r.logger.Debug(
			"Removing stale router IP from cilium_host device",
			logfields.IPAddr, a.IP,
		)
		if e := netlink.AddrDel(l, &a); e != nil {
			err = errors.Join(err, resiliency.Retryable(fmt.Errorf("failed to remove IP %s: %w", a.IP, e)))
		}
	}

	return err
}

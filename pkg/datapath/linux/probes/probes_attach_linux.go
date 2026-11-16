// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	bigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/types"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/netns"
)

// HaveTCBPF returns nil if the running kernel supports attaching a bpf filter
// to a clsact qdisc.
var HaveTCBPF = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SchedCLS)
	if err != nil {
		return err
	}
	defer prog.Close()

	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()

	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: 1, // lo
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: 1, // lo
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		DirectAction: true,
	}

	return ns.Do(func() error {
		if err := netlink.QdiscReplace(qdisc); err != nil {
			return fmt.Errorf("creating clsact qdisc: %w: %w", err, ErrNotSupported)
		}

		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("attaching bpf tc filter: %w: %w", err, ErrNotSupported)
		}

		return nil
	})
})

// HaveTCX returns nil if the running kernel supports attaching bpf programs to
// tcx hooks.
var HaveTCX = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SchedCLS)
	if err != nil {
		return err
	}
	defer prog.Close()

	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()

	// link.AttachTCX already performs its own feature detection and returns
	// ebpf.ErrNotSupported if the host kernel doesn't have tcx.
	return ns.Do(func() error {
		l, err := link.AttachTCX(link.TCXOptions{
			Program:   prog,
			Attach:    ebpf.AttachTCXIngress,
			Interface: 1, // lo
			Anchor:    link.Tail(),
		})
		if err != nil {
			return fmt.Errorf("creating link: %w", err)
		}
		if err := l.Close(); err != nil {
			return fmt.Errorf("closing link: %w", err)
		}

		return nil
	})
})

// HaveNetkit returns nil if the running kernel supports attaching bpf programs
// to netkit devices.
var HaveNetkit = sync.OnceValue(func() error {
	prog, err := newProgram(ebpf.SchedCLS)
	if err != nil {
		return err
	}
	defer prog.Close()

	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()

	return ns.Do(func() error {
		l, err := link.AttachNetkit(link.NetkitOptions{
			Program:   prog,
			Attach:    ebpf.AttachNetkitPrimary,
			Interface: math.MaxInt,
		})
		// We rely on this being checked during the syscall. With
		// an otherwise correct payload we expect ENODEV here as
		// an indication that the feature is present.
		if errors.Is(err, syscall.ENODEV) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("creating link: %w", err)
		}
		if err := l.Close(); err != nil {
			return fmt.Errorf("closing link: %w", err)
		}

		return fmt.Errorf("unexpected success: %w", err)
	})
})

// HaveIPv6Support tests whether kernel can open an IPv6 socket. This will
// also implicitly auto-load IPv6 kernel module if available and not yet
// loaded.
func HaveIPv6Support() error {
	fd, err := unix.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) {
		return ErrNotSupported
	}
	unix.Close(fd)
	return nil
}

// Probes whether the kernel supports BIG TCP for VXLAN and GENEVE.
var HaveBIGTCPTunnel = sync.OnceValue(func() error {
	ns, err := netns.New()
	if err != nil {
		return fmt.Errorf("create netns: %w", err)
	}
	defer ns.Close()

	var h *netlink.Handle
	if err := ns.Do(func() (err error) {
		h, err = netlink.NewHandle()
		return err
	}); err != nil {
		return fmt.Errorf("create netlink handle: %w", err)
	}
	defer h.Close()

	const probeNetdev = "probe"

	dev := &netlink.Geneve{
		LinkAttrs: netlink.LinkAttrs{
			Name: probeNetdev,
		},
		Dport: defaults.TunnelPortGeneve,
	}

	if err := h.LinkAdd(dev); err != nil {
		return fmt.Errorf("failed to create a probe GENEVE device: %w", err)
	}

	link, err := safenetlink.WithRetryResult(func() (netlink.Link, error) {
		//nolint:forbidigo
		return h.LinkByName(probeNetdev)
	})
	if err != nil {
		return fmt.Errorf("failed to fetch the probe GENEVE device: %w", err)
	}

	// (Pending) Kernel commit XXXXXXXXXXXX ("geneve: Enable BIG TCP packets").
	//
	// VXLAN tunnels are less suitable as a probe, because they may call
	// netif_inherit_tso_max() and inherit tso_max_size from the physical
	// device, which is likely to be bigger than 64k, even before the kernel
	// support for BIG TCP for VXLAN has been added. Setting gso_max_size
	// to a bigger value on such kernels doesn't make it work, but leads to
	// packet drops instead.
	//
	// GENEVE, on the other hand, doesn't do netif_inherit_tso_max(), so we
	// can reliably check its tso_max_size (65536 meaning pre BIG TCP
	// support; 524280 meaning post BIG TCP support).
	if link.Attrs().TSOMaxSize > bigtcp.GROGSOLegacyMaxSize {
		return nil
	} else {
		return ErrNotSupported
	}
})

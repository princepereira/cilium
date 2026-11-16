// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package dnsproxy

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

// doSetSoMarks sets the socket options needed for a transparent proxy to integrate
// its upstream connections with the datapath.
func doSetSoMarks(fd int, ipFamily ipfamily.IPFamily, secId identity.NumericIdentity) error {
	// Set SO_MARK to allow datapath to know these upstream packets from an egress proxy
	mark := linux_defaults.MakeMagicMark(linux_defaults.MagicMarkEgress, secId)
	err := unix.SetsockoptUint64(fd, syscall.SOL_SOCKET, unix.SO_MARK, uint64(mark))
	if err != nil {
		return fmt.Errorf("error setting SO_MARK: %w", err)
	}

	// Rest of the options are only set in the transparent mode.
	if !option.Config.DNSProxyEnableTransparentMode {
		return nil
	}

	// Set IP_TRANSPARENT to be able to use a non-host address as the source address
	if err := unix.SetsockoptInt(fd, ipFamily.SocketOptsFamily, ipFamily.SocketOptsTransparent, 1); err != nil {
		return fmt.Errorf("setsockopt(IP_TRANSPARENT) for %s failed: %w", ipFamily.Name, err)
	}

	// Set SO_REUSEADDR to allow binding to an address that is already used by some other
	// connection in a lingering state. This is needed in cases where we close a client
	// connection but the client issues new requests re-using its source port. In that case we
	// need to be able to reuse the address likely very soon after the prior close, which may
	// not be allowed without this option.
	if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("setsockopt(SO_REUSEADDR) failed: %w", err)
	}

	// Set SO_REUSEPORT to allow two active connections to bind to the same address and
	// port. Normally this would not be needed, but is set to allow a new connection to be
	// created on a port where the old connection may not yet be closed. If two UDP sockets
	// using the same port due to this option were reading at the same time, the OS stack would
	// distribute incoming packets to them essentially randomly. We do not want that, so we
	// strive to avoid that situation. This may be helpful in avoiding bind errors in some cases
	// regardless.
	if !option.Config.EnableBPFTProxy {
		if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return fmt.Errorf("setsockopt(SO_REUSEPORT) failed: %w", err)
		}
	}

	// Set SO_LINGER to ensure the TCP socket is closed and ready to be re-used in case
	// the client reuses the same source port in short succession (this is e.g. the case
	// with glibc). If SO_LINGER is not used, the old socket might have not yet reached
	// the TIME_WAIT state by the time we are trying to reuse the port on a new socket.
	// If that happens, the connect() call will fail with EADDRNOTAVAIL.
	// Note that the linger timeout can also be set to 0, in which case the socket is
	// terminated forcefully with a TCP RST and thus can also be reused immediately.
	if linger := option.Config.DNSProxySocketLingerTimeout; linger >= 0 {
		err = unix.SetsockoptLinger(fd, syscall.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{
			Onoff:  1,
			Linger: int32(linger),
		})
		if err != nil {
			return fmt.Errorf("setsockopt(SO_LINGER) failed: %w", err)
		}
	}

	return nil
}

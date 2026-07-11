// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
)

// setSoMarks sets the socket options needed for a transparent proxy to integrate it's upstream
// (forwarded) connection with Cilium datapath. Some considerations for this design:
//
//   - Since a transparent proxy must reuse the original source IP address (and we must also
//     intercept the responses), we instruct the host networking namespace to allow binding the
//     local address to a foreign address and to receive packets destined to a non-local (foreign)
//     IP address of the source pod via the IP_TRANSPARENT socket option.
//
//   - In order to NOT hijack some random by-standing traffic going to the original pod, we must also
//     use the original port number.
//
//   - (DNS) clients use ephemeral source ports, i.e., the port can be different in every
//     request. Typically, a DNS resolver library uses the same ephemeral port only for requests
//     from a single "gethostbyname" API call, or equivalent.
//
//   - To be able to receive responses to the ephemeral source port, we must have a socket bound to
//     that address:port (for UDP), or a connection from that address:port to the DNS server
//     address:port (for TCP).
//
//   - This leads to a new DNS client and socket for every different original source address -
//     ephemeral port pair we see. We also need to make sure these were actually used to communicate
//     with the DNS server, so we use the whole 5-tuple as a key.
//
// Why can't we keep DNS clients pooled and ready to receive traffic between client requests?
//
//   - We have no guarantees that the source pod will keep on using the same ephemeral port in
//     future. We've had upstream socket bind errors (in Envoy, where we have operated in this mode
//     for years already) when a client pod has rapidly cycled through its ephemeral port space,
//     e.g. when performing netperf CRR or similar performance tests.
//
//   - We could try to keep the client and its bound socket around for some minimal time to save
//     resources when a DNS resolver is enumerating through its domain suffix list, where it seems
//     likely that the same source ephemeral port is going to be reused until the resolver gets an
//     actual result with an IPv4/6 address or quits trying. It might be safe to close the client
//     socket only after a response with the `A`/`AAAA` records have been passed back to the pod,
//     or after a timeout of a few milliseconds. This would be something we currently don't do and
//     is prone to socket bind errors, so this is left for a later exercise.
//
//   - So the client socket can not be left lingering around, as it causes network traffic destined
//     for the source pod to be intercepted to the dnsproxy, which is exactly what we want but only
//     until a DNS response has been received.
func setSoMarks(fd int, ipFamily ipfamily.IPFamily, secId identity.NumericIdentity) error {
	// Set SO_MARK to allow datapath to know these upstream packets from an egress proxy
	mark := linux_defaults.MakeMagicMark(linux_defaults.MagicMarkEgress, secId)
	err := unix.SetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_MARK, uint64(mark))
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
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
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
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
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
		err = unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{
			Onoff:  1,
			Linger: int32(linger),
		})
		if err != nil {
			return fmt.Errorf("setsockopt(SO_LINGER) failed: %w", err)
		}
	}

	return nil
}

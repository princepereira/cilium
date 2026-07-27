// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package dnsproxy

import (
	"net"

	"github.com/cilium/dns"
)

// ReadRequest is a no-op. On Linux dns.SessionUDP is an interface, so its zero
// value is nil.
func (*noopSessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, dns.SessionUDP, error) {
	return nil, nil, nil
}

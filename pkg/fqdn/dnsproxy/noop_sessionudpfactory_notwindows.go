// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package dnsproxy

import (
	"net"

	"github.com/cilium/dns"
)

// ReadRequest returns a nil SessionUDP; on non-Windows platforms dns.SessionUDP
// is an interface, so nil is a valid value.
func (*noopSessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, dns.SessionUDP, error) {
	return nil, nil, nil
}

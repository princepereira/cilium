// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package dnsproxy

import (
	"net"

	"github.com/cilium/dns"
)

// ReadRequest returns an empty SessionUDP; on Windows dns.SessionUDP is a
// struct value rather than an interface, so nil cannot be returned.
func (*noopSessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, dns.SessionUDP, error) {
	return nil, dns.SessionUDP{}, nil
}

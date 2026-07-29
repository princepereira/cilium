// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package dnsproxy

import (
	"net"

	"github.com/cilium/dns"
)

// ReadRequest is a no-op. On non-Linux platforms dns.SessionUDP is a struct, so
// its zero value is an empty struct value.
func (*noopSessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, dns.SessionUDP, error) {
	return nil, dns.SessionUDP{}, nil
}

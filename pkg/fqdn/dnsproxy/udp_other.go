// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package dnsproxy

import (
	"log/slog"
	"net"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
)

// listenConfig returns a plain net.ListenConfig on non-Linux platforms. The
// transparent-proxy socket options (IP_TRANSPARENT, SO_MARK, SO_REUSEPORT) have
// no portable equivalent, so they are omitted.
func listenConfig(mark uint32, ipFamily ipfamily.IPFamily) *net.ListenConfig {
	return &net.ListenConfig{}
}

// NewSessionUDPFactory returns a no-op session factory on non-Linux platforms.
// The transparent DNS proxy relies on Linux raw sockets and out-of-band
// original-destination data, which are unavailable here.
func NewSessionUDPFactory(logger *slog.Logger, ipFamily ipfamily.IPFamily) (dns.SessionUDPFactory, error) {
	return &noopSessionUDPFactory{}, nil
}

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

// NewSessionUDPFactory returns a no-op SessionUDPFactory on platforms that lack
// the Linux raw-socket/transparent-proxy facilities required by the real
// implementation.
func NewSessionUDPFactory(logger *slog.Logger, ipFamily ipfamily.IPFamily) (dns.SessionUDPFactory, error) {
	return &noopSessionUDPFactory{}, nil
}

// listenConfig returns a plain net.ListenConfig on platforms that lack the
// Linux SO_MARK/transparent-proxy socket control used by the real
// implementation.
func listenConfig(mark uint32, ipFamily ipfamily.IPFamily) *net.ListenConfig {
	return &net.ListenConfig{}
}

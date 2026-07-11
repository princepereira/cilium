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

// NewSessionUDPFactory returns a no-op UDP session factory on non-Linux
// platforms. The transparent proxy raw-socket response path used on Linux
// relies on socket options and out-of-band data that are not available here.
func NewSessionUDPFactory(logger *slog.Logger, ipFamily ipfamily.IPFamily) (dns.SessionUDPFactory, error) {
	return &noopSessionUDPFactory{}, nil
}

// listenConfig returns a default ListenConfig on non-Linux platforms, since the
// transparent proxy socket options are Linux-only.
func listenConfig(mark uint32, ipFamily ipfamily.IPFamily) *net.ListenConfig {
	return &net.ListenConfig{}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package dnsproxy

import (
	"github.com/cilium/dns"
)

// noopSessionUDP returns a nil SessionUDP. On non-Windows platforms the
// cilium/dns SessionUDP type is an interface, so nil is a valid value.
func noopSessionUDP() dns.SessionUDP {
	return nil
}

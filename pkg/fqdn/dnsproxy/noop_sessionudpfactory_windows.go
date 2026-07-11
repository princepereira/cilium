// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package dnsproxy

import (
	"github.com/cilium/dns"
)

// noopSessionUDP returns an empty SessionUDP value. On Windows the cilium/dns
// SessionUDP type is a (non-pointer) struct, so the zero value must be returned
// instead of nil.
func noopSessionUDP() dns.SessionUDP {
	return dns.SessionUDP{}
}

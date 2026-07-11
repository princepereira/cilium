// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package dnsproxy

import (
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
	"github.com/cilium/cilium/pkg/identity"
)

// setSoMarks is a no-op on non-Linux platforms, where the transparent proxy
// socket options (SO_MARK, IP_TRANSPARENT, SO_REUSEADDR, SO_REUSEPORT, SO_LINGER)
// are not available.
func setSoMarks(fd int, ipFamily ipfamily.IPFamily, secId identity.NumericIdentity) error {
	return nil
}

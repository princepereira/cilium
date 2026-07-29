// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package dnsproxy

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
)

// setSoMarks is a no-op on platforms that lack the Linux socket options
// (SO_MARK, IP_TRANSPARENT, SO_REUSEADDR/PORT, SO_LINGER) used to integrate the
// transparent DNS proxy with the Cilium datapath.
func setSoMarks(fd int, ipFamily ipfamily.IPFamily, secId identity.NumericIdentity) error {
	return nil
}

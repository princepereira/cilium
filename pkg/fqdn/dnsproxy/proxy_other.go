// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package dnsproxy

import (
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
	"github.com/cilium/cilium/pkg/identity"
)

// doSetSoMarks is a no-op on non-Linux platforms, where the SO_MARK/IP_TRANSPARENT
// socket options used for transparent proxying are unavailable.
func doSetSoMarks(fd int, ipFamily ipfamily.IPFamily, secId identity.NumericIdentity) error {
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package hostfirewallbypass

import (
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/identity"
)

func setProxyEgressMark(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		mark := linux_defaults.MakeMagicMark(linux_defaults.MagicMarkEgress, identity.ReservedIdentityHost)
		soerr = unix.SetsockoptUint64(int(su), unix.SOL_SOCKET, unix.SO_MARK, uint64(mark))
	}); err != nil {
		return err
	}
	return soerr
}

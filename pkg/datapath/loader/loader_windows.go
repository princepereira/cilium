// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

// This is a compile-only stub of the datapath loader for non-Linux platforms.
// The real loader attaches eBPF programs to the kernel via tc/tcx/xdp/netkit
// and manages netlink qdiscs, none of which exist off Linux. Only the handful
// of symbols referenced by cross-platform consumers are provided here.

package loader

import (
	"errors"
	"log/slog"
	"net"

	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/bpf"
)

var errNotSupported = errors.New("datapath loader is not supported on this platform")

// FilterSetter mirrors the Linux definition; it sets a socket filter.
type FilterSetter func(af uint8, addr net.IP, port uint16) error

// LoadSockTerm is not supported on non-Linux platforms.
func LoadSockTerm(l *slog.Logger, sockRevNat4, sockRevNat6 *bpf.Map) (*bpfgen.SockTermPrograms, FilterSetter, error) {
	return nil, nil, errNotSupported
}

// DeviceHasSKBProgramLoaded is not supported on non-Linux platforms.
func DeviceHasSKBProgramLoaded(device string, checkEgress bool) (bool, error) {
	return false, errNotSupported
}

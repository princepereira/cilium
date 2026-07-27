// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

// This is a compile-only stub of the datapath loader for non-Linux platforms.
// The real loader attaches eBPF programs to the kernel via tc/tcx/xdp/netkit
// and manages netlink qdiscs, none of which exist off Linux. Only the handful
// of symbols referenced by cross-platform consumers are provided here.

package loader

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/lock"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
)

var errNotSupported = errors.New("datapath loader is not supported on this platform")

// FilterSetter mirrors the Linux definition; it sets a socket filter.
type FilterSetter func(af uint8, addr net.IP, port uint16) error

// compilationLock mirrors the Linux definition. It guards datapath
// compilation; on non-Linux platforms no compilation happens but the lock is
// still provided so cross-platform consumers can depend on it.
type compilationLock struct {
	lock.RWMutex
}

// NewCompilationLock returns a CompilationLock usable on any platform.
func NewCompilationLock() types.CompilationLock {
	return &compilationLock{}
}

// stubLoader is a non-functional loader for non-Linux platforms. The real
// loader compiles and attaches eBPF programs to the kernel, which is not
// possible off Linux. All datapath-affecting operations report the closed
// datapath state or an unsupported error; readers that only need identifiers
// (e.g. CallsMapPath) still work.
type stubLoader struct{}

// NewLoader returns a non-functional loader for non-Linux platforms.
func NewLoader() types.Loader { return &stubLoader{} }

func (*stubLoader) CallsMapPath(id uint16) string { return "" }

func (*stubLoader) Unload(ep endpoint.Endpoint) {}

func (*stubLoader) HostDatapathInitialized() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (*stubLoader) ReloadDatapath(ctx context.Context, ep endpoint.Endpoint, cfg *config.Config, stats *metrics.SpanStat) (string, error) {
	return "", errNotSupported
}

func (*stubLoader) EndpointHash(cfg endpoint.Config, lnCfg *config.Config) (string, error) {
	return "", errNotSupported
}

func (*stubLoader) ReinitializeHostDev(ctx context.Context, mtu int) error { return nil }

func (*stubLoader) Reinitialize(ctx context.Context, cfg *config.Config, tunnelConfig tunnel.Config, iptMgr iptables.Manager, p proxytypes.Proxy, bigtcp bigtcp.Config) error {
	return nil
}

func (*stubLoader) WriteEndpointConfig(w io.Writer, cfg endpoint.Config) error {
	return errNotSupported
}

// LoadSockTerm is not supported on non-Linux platforms.
func LoadSockTerm(l *slog.Logger, sockRevNat4, sockRevNat6 *bpf.Map) (*bpfgen.SockTermPrograms, FilterSetter, error) {
	return nil, nil, errNotSupported
}

// DeviceHasSKBProgramLoaded is not supported on non-Linux platforms.
func DeviceHasSKBProgramLoaded(device string, checkEgress bool) (bool, error) {
	return false, errNotSupported
}

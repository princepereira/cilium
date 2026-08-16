// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package loader

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	bpfgen "github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	linuxconfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	endpointstate "github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/node/manager"
	"github.com/cilium/cilium/pkg/promise"
	proxy "github.com/cilium/cilium/pkg/proxy/types"
)

// errUnsupported is returned by loader operations that are not supported on
// non-Linux platforms.
var errUnsupported = errors.New("datapath loader is not supported on this platform")

// StandardCFlags is the set of clang flags used to compile BPF C programs. It
// is platform-neutral data, exposed for tooling.
var StandardCFlags = []string{"-O2", "--target=bpf", "-std=gnu99",
	"-nostdinc",
	"-ftrap-function=__undefined_trap",
	"-Wall", "-Wextra", "-Werror", "-Wshadow",
	"-Wno-address-of-packed-member",
	"-Wno-unknown-warning-option",
	"-Wno-gnu-variable-sized-type-not-at-end",
	"-Wimplicit-int-conversion",
	"-Wenum-conversion",
	"-Wimplicit-fallthrough"}

// Cell provides a no-op loader on non-Linux platforms.
var Cell = cell.Module(
	"loader",
	"Loader",

	cell.Provide(NewLoader),
	cell.Provide(NewCompilationLock),
)

// Params are the dependencies of the loader. Mirrors the Linux Params so that
// the hive dependency graph is identical across platforms.
type Params struct {
	cell.In

	MapRegistry        *registry.MapRegistry
	JobGroup           job.Group
	Logger             *slog.Logger
	Sysctl             sysctl.Sysctl
	Prefilter          prefilter.PreFilter
	CompilationLock    types.CompilationLock
	ConfigWriter       linuxconfig.Writer
	NodeConfigNotifier *manager.NodeConfigNotifier
	RouteManager       *routeReconciler.DesiredRouteManager
	DB                 *statedb.DB
	Devices            statedb.Table[*tables.Device]
	EPRestorer         promise.Promise[endpointstate.Restorer]
	BIGTCPConfig       bigtcp.Config

	// Force map initialisation before loader.
	bpf.MapGroup
}

// loader is a no-op datapath loader for non-Linux platforms.
type loader struct {
	logger            *slog.Logger
	hostDpInitialized chan struct{}
}

// NewLoader returns a new no-op loader.
func NewLoader(p Params) types.Loader {
	return &loader{
		logger:            p.Logger,
		hostDpInitialized: make(chan struct{}),
	}
}

// compilationLock is a no-op implementation of types.CompilationLock.
type compilationLock struct {
	lock.RWMutex
}

// NewCompilationLock returns a new compilation lock.
func NewCompilationLock() types.CompilationLock {
	return &compilationLock{}
}

func (l *loader) CallsMapPath(id uint16) string {
	return ""
}

func (l *loader) Unload(ep endpoint.Endpoint) {}

func (l *loader) HostDatapathInitialized() <-chan struct{} {
	return l.hostDpInitialized
}

func (l *loader) ReloadDatapath(ctx context.Context, ep endpoint.Endpoint, cfg *config.Config, stats *metrics.SpanStat) (string, error) {
	return "", errUnsupported
}

func (l *loader) EndpointHash(cfg endpoint.Config, lnCfg *config.Config) (string, error) {
	return "", errUnsupported
}

func (l *loader) ReinitializeHostDev(ctx context.Context, mtu int) error {
	return errUnsupported
}

func (l *loader) Reinitialize(ctx context.Context, cfg *config.Config, tunnelConfig tunnel.Config, iptMgr iptables.Manager, p proxy.Proxy, bigtcp bigtcp.Config) error {
	return errUnsupported
}

func (l *loader) WriteEndpointConfig(w io.Writer, cfg endpoint.Config) error {
	return errUnsupported
}

// FilterSetter sets the socket filter for the socket termination programs.
type FilterSetter func(af uint8, addr netip.Addr, port uint16) error

// LoadSockTerm is not supported on non-Linux platforms.
func LoadSockTerm(l *slog.Logger, sockRevNat4, sockRevNat6 *bpf.Map) (*bpfgen.SockTermPrograms, FilterSetter, error) {
	return nil, nil, errUnsupported
}

// DetachXDP is a no-op on non-Linux platforms.
func DetachXDP(ifaceName string, bpffsBase, progName string) error {
	return nil
}

// DeviceHasSKBProgramLoaded is not supported on non-Linux platforms.
func DeviceHasSKBProgramLoaded(device string, checkEgress bool) (bool, error) {
	return false, errUnsupported
}

// ListCiliumTCFilters is not supported on non-Linux platforms.
func ListCiliumTCFilters(device netlink.Link, parent uint32) ([]*netlink.BpfFilter, error) {
	return nil, errUnsupported
}

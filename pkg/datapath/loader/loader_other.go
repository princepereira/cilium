// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package loader

import (
	"context"
	"errors"
	"io"

	"github.com/cilium/hive/cell"

	datapathconfig "github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	proxy "github.com/cilium/cilium/pkg/proxy/types"
)

// errUnsupported is returned by the loader stubs on platforms where eBPF
// datapath loading is not available (i.e. non-Linux).
var errUnsupported = errors.New("datapath loader is not supported on this platform")

// Cell provides a non-functional loader on non-Linux platforms so that the
// hive graph can still be constructed. All datapath operations return an
// unsupported error.
var Cell = cell.Module(
	"loader",
	"Loader",

	cell.Provide(newStubLoader),
	cell.Provide(NewCompilationLock),
)

func newStubLoader() types.Loader {
	return &loader{hostDpInitialized: make(chan struct{})}
}

// loader is a no-op implementation of types.Loader for non-Linux platforms.
type loader struct {
	hostDpInitialized chan struct{}
}

func (l *loader) CallsMapPath(id uint16) string { return "" }

func (l *loader) Unload(ep endpoint.Endpoint) {}

func (l *loader) HostDatapathInitialized() <-chan struct{} { return l.hostDpInitialized }

func (l *loader) ReloadDatapath(ctx context.Context, ep endpoint.Endpoint, cfg *datapathconfig.Config, stats *metrics.SpanStat) (string, error) {
	return "", errUnsupported
}

func (l *loader) EndpointHash(cfg endpoint.Config, lnCfg *datapathconfig.Config) (string, error) {
	return "", errUnsupported
}

func (l *loader) ReinitializeHostDev(ctx context.Context, mtu int) error {
	return errUnsupported
}

func (l *loader) Reinitialize(ctx context.Context, cfg *datapathconfig.Config, tunnelConfig tunnel.Config, iptMgr iptables.Manager, p proxy.Proxy, bigtcp bigtcp.Config) error {
	return errUnsupported
}

func (l *loader) WriteEndpointConfig(w io.Writer, cfg endpoint.Config) error {
	return errUnsupported
}

// DetachXDP is a no-op on non-Linux platforms.
func DetachXDP(ifaceName string, bpffsBase, progName string) error {
	return errUnsupported
}

// DeviceHasSKBProgramLoaded is unsupported on non-Linux platforms.
func DeviceHasSKBProgramLoaded(device string, checkEgress bool) (bool, error) {
	return false, errUnsupported
}

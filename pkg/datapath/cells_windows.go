// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package datapath

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/connector"
	fakeconnector "github.com/cilium/cilium/pkg/datapath/connector/fake"
	"github.com/cilium/cilium/pkg/datapath/gneigh"
	fakegneigh "github.com/cilium/cilium/pkg/datapath/gneigh/fake"
	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	fakebigtcp "github.com/cilium/cilium/pkg/datapath/linux/bigtcp/fake"
	fakeipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/fake"
	ipsecTypes "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	fakesysctl "github.com/cilium/cilium/pkg/datapath/linux/sysctl/fake"
	"github.com/cilium/cilium/pkg/datapath/neighbor"
	dpnode "github.com/cilium/cilium/pkg/datapath/node"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/datapath/xdp"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/subnet"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/mtu"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"

	"github.com/cilium/cilium/api/v1/models"
)

// disabledWireguardConfig is a minimal wgTypes.Config implementation used on
// platforms where the WireGuard agent is not available. It reports WireGuard
// as always disabled.
type disabledWireguardConfig struct{}

func (disabledWireguardConfig) Enabled() bool { return false }

// disabledWireguardAgent is a no-op wgTypes.Agent used on platforms where the
// WireGuard agent is not available.
type disabledWireguardAgent struct{}

func (disabledWireguardAgent) Enabled() bool { return false }
func (disabledWireguardAgent) Status(bool) (*models.WireguardStatus, error) {
	return nil, nil
}
func (disabledWireguardAgent) IfaceIndex() (uint32, error)                 { return 0, nil }
func (disabledWireguardAgent) IfaceBufferMargins() (uint16, uint16, error) { return 0, 0, nil }

// disabledIPsecConfig is a minimal ipsec.Config implementation used on platforms
// where IPsec is not available. It reports IPsec as always disabled.
type disabledIPsecConfig struct{}

func (disabledIPsecConfig) Enabled() bool                                         { return false }
func (disabledIPsecConfig) UseCiliumInternalIP() bool                             { return false }
func (disabledIPsecConfig) DNSProxyInsecureSkipTransparentModeCheckEnabled() bool { return false }

// Cell provides the datapath module on non-Linux platforms.
//
// The Linux datapath (see cells.go) wires together a large set of BPF- and
// netlink-based subsystems that only build and run on Linux. On other
// platforms (e.g. Windows) those subsystems are not available, so this cell
// provides only the platform-neutral pieces that the rest of the agent hive
// depends on, plus lightweight stubs for the datapath types consumed by
// cross-platform components (e.g. the node manager). Native, platform-specific
// datapath functionality (e.g. via HNS/HCS on Windows) is wired in
// incrementally through dedicated *_windows.go implementations.
var Cell = cell.Module(
	"datapath",
	"Datapath",

	// Tunnel protocol configuration. Pure configuration, builds on all platforms.
	tunnel.Cell,

	// IP sets management. Uses the ipset executable and a StateDB reconciler;
	// builds on all platforms (reconciliation is a no-op when the tool is absent).
	ipset.Cell,

	// MTU provides the MTU configuration of the node.
	mtu.Cell,

	// Provides the Table[NodeAddress] and the controller that populates it from
	// Table[*Device].
	tables.NodeAddressCell,

	// Provides the legacy node.Addressing accessor over Table[NodeAddress].
	dpnode.AddressingCell,

	// Provides the DirectRoutingDevice selection logic.
	tables.DirectRoutingDeviceCell,

	// Provides the desired route table and a reconciler. On non-Linux platforms
	// the reconciler is a no-op (routes are tracked but never programmed).
	routeReconciler.Cell,

	// The monitor agent, which multicasts cilium and agent events to its
	// subscribers. On non-Linux platforms it works only for agent events since
	// there is no eventsmap.
	monitorAgent.Cell,

	// Provides a cache of link names to ifindex mappings.
	link.Cell,

	// Neighbor subsystem. On non-Linux platforms this provides the forwardable
	// IP table/manager and config, but omits the netlink neighbor reconciler.
	neighbor.Cell,

	// XDP configuration. Acceleration is effectively disabled off Linux.
	xdp.Cell,

	// Subnet table (BPF map and reconciler are Linux-only).
	subnet.Cell,

	// Provides the lxc / endpoints map. Backed by the in-memory BPF map
	// implementation on non-Linux platforms (see pkg/bpf).
	lxcmap.Cell,

	// Provide empty devices and routes tables. On Linux the devices controller
	// populates these from netlink; on other platforms no device or route
	// discovery is performed, so we simply register empty tables for
	// cross-platform consumers to read.
	cell.ProvidePrivate(tables.NewDeviceTable),
	cell.ProvidePrivate(tables.NewRouteTable),
	cell.Provide(func(t statedb.RWTable[*tables.Device]) statedb.Table[*tables.Device] {
		return t
	}),
	cell.Provide(func(t statedb.RWTable[*tables.Route]) statedb.Table[*tables.Route] {
		return t
	}),

	// Provide the L2 announcement table. On Linux the l2responder reconciles
	// this into the BPF L2 responder map; off Linux it is only tracked.
	cell.Provide(tables.NewL2AnnounceTable),
	cell.Provide(statedb.RWTable[*tables.L2AnnounceEntry].ToTable),

	// WireGuard is not available on non-Linux platforms; provide a disabled
	// config and a no-op agent.
	cell.Provide(func() wgTypes.Config { return disabledWireguardConfig{} }),
	cell.Provide(func() wgTypes.Agent { return disabledWireguardAgent{} }),

	// Native Windows datapath node handler (see nodehandler_hns.go). On Linux
	// this is the netlink-based node handler; here node events are tracked in
	// memory and remote-node pod CIDRs are programmed as HNS RemoteSubnetRoute
	// policies (best-effort; a no-op when HNS is unavailable).
	cell.Provide(newHNSNodeHandler),

	// IPsec is not available on non-Linux platforms; provide a disabled config
	// and a no-op agent.
	cell.Provide(func() ipsecTypes.Config { return disabledIPsecConfig{} }),
	cell.Provide(func() ipsecTypes.Agent { return &fakeipsec.Agent{} }),

	// The bandwidth manager provides EDT-based rate-limiting on Linux; on other
	// platforms a disabled, no-op Manager is provided.
	bandwidth.Cell,

	// Stub REST API handlers for datapath endpoints backed by BPF on Linux.
	cell.Provide(newStubAPIHandlers),

	// Datapath dependencies required to construct endpoints. Non-functional on
	// non-Linux platforms.
	cell.Provide(newEndpointDatapathDeps),

	// sysctl is not meaningful off Linux; provide a no-op implementation.
	cell.Provide(func() sysctl.Sysctl { return &fakesysctl.Sysctl{} }),

	// BIG TCP and connector configuration. On non-Linux platforms these are
	// disabled/no-op defaults.
	cell.Provide(func() bigtcp.Config { return &fakebigtcp.Config{} }),
	cell.Provide(func() bigtcp.Features { return &fakebigtcp.UserConfig{} }),
	cell.Provide(func() connector.Config { return fakeconnector.NewVeth() }),
	cell.Provide(func() gneigh.L2PodAnnouncementConfig { return &fakegneigh.Config{} }),

	// Fake/nil BPF maps for cross-platform consumers.
	cell.Provide(newMapStubs),

	// Native Windows container query manager (HCS). Provided for endpoint /
	// workload correlation; disabled no-op off Windows or without HCS. The
	// invoke forces construction and logs availability at startup.
	cell.Provide(newHCSManager),
	cell.Invoke(logHCSStatus),
)

<overview>
The user wants to make `cilium-agent` (the `./daemon` binary) build AND run on Windows nodes while preserving Linux functionality, using build-tag separation (`_linux.go`/`_windows.go`/`_unspecified.go`). Strategy: real code stays Linux-tagged; Windows gets best-effort implementations (via cncshim/hnslib/hcsshim per user guidance) or disabled/no-op stubs where BPF/netlink functionality isn't feasible. **The daemon already COMPILES for both GOOS=windows and GOOS=linux** (achieved in a prior session). This session's focus: making it **runnable** on Windows by completing the hive dependency-injection graph so the agent can initialize.
</overview>

<history>
1. **Tested Windows binary runnability** (`ciliumd.exe --help`)
   - First run panicked: my bandwidth module description `"...(disabled on this platform)"` contained parentheses, violating hive's Module description regex `^[a-zA-Z0-9_\- ]{1,80}$`.
   - Fixed description to use ` - disabled on this platform`. `--help` then worked fully — the entire hive `init()` completes cleanly on Windows.

2. **Ran `ciliumd.exe hive` to validate the full DI graph** — this revealed a long chain of missing provider types (the empty Windows datapath cell dropped everything). Iteratively resolved each missing type by building up `pkg/datapath/cells_windows.go` and adding stub/fake providers. The loop was: `go build -o $env:TEMP\ciliumd.exe ./daemon` → `ciliumd.exe hive` → read "missing type: X" → find X's Linux provider → add cross-platform cell or stub → rebuild. Each rebuild takes ~2-3 min.

   Missing types resolved in order:
   - `tunnel.Config`, `ipset.Manager`, `statedb.Table[*Device]`, `wgTypes.Config` → added tunnel.Cell, ipset.Cell, mtu.Cell, device table stub, disabled wireguard config
   - `agent.Agent` → added monitorAgent.Cell
   - `ipsec/types.Config` → disabled ipsec config stub
   - `statedb.Table[NodeAddress]` → tables.NodeAddressCell + DirectRoutingDeviceCell
   - `statedb.Table[*Route]` → route table stub
   - 7 REST API handlers (GetMap*, GetNodeIds, *Prefilter) → `api_handlers_windows.go` returning `middleware.NotImplemented`
   - endpoint creator deps (lxcmap.Map, types.Loader, Orchestrator, CompilationLock, bandwidth.Manager, iptables.Manager, policymap.Factory, ctmap.GCRunner) → `endpoint_datapath_windows.go` + stub Loader in loader_windows.go
   - `*reconciler.DesiredRouteManager` → routeReconciler.Cell (already cross-platform)
   - `node.Addressing`, `sysctl.Sysctl` → dpnode.AddressingCell + fake sysctl
   - `ipsec.Agent` (via mtu) → fakeipsec.Agent
   - `bigtcp.Config`, `connector.Config` → fakes
   - `wgTypes.Agent`, `node.Handler` (via daemonLegacyInit) → disabled wg agent + fakenode.Handler subscribed to node manager
   - `authmap.Map` (+ batch of BPF map fakes) → `maps_windows.go`
   - `*link.LinkCache` → link.Cell (already cross-platform via `_unspecified.go`)
   - `*neighbor.ForwardableIPManager` → neighbor.Cell
   - `xdp.Config` → xdp.Cell
   - `RWTable[*L2AnnounceEntry]` → L2 announce table stub
   - `bigtcp.Features`, `gneigh.L2PodAnnouncementConfig` → fakes
   - `RWTable[subnet.SubnetTableEntry]` → **just split subnet.Cell** (tagged cell.go linux, created cell_windows.go providing only the table)

   **Last action (incomplete): wired `subnet.Cell` into cells_windows.go. Not yet rebuilt/re-validated.**
</history>

<work_done>
Files created this session:
- `pkg/datapath/api_handlers_windows.go` — provides 7 stub REST handlers (GetMap/GetMapName/GetMapNameEvents/GetNodeIds/Get/Patch/DeletePrefilter) returning `middleware.NotImplemented("not supported on this platform")`.
- `pkg/datapath/endpoint_datapath_windows.go` — `newEndpointDatapathDeps()` provides Loader (loader.NewLoader), Orchestrator (fakeendpoint.FakeOrchestrator), CompilationLock (loader.NewCompilationLock), IPTablesManager (fakeiptables.NewManager), CTMapGC (ctmap.NewFakeGCRunner), PolicyMapFactory (nil), LxcMap (nil).
- `pkg/datapath/maps_windows.go` — `newMapStubs()` provides signalmap.Map (fake), authmap.Map (fake), encrypt.EncryptMap (fake), egressmap PolicyMap4/6 (nil), nat.NatMap4/6 (nil).
- `pkg/maps/subnet/cell_windows.go` — `//go:build !linux` Cell providing only `newSubnetEntryTable` + `RWTable[SubnetTableEntry].ToTable` (no BPF map/reconciler).

Files heavily modified:
- `pkg/datapath/cells_windows.go` — Grew from empty module to a full Windows datapath cell. Now includes: tunnel.Cell, ipset.Cell, mtu.Cell, monitorAgent.Cell, link.Cell, neighbor.Cell, xdp.Cell, subnet.Cell, tables.NodeAddressCell, dpnode.AddressingCell, tables.DirectRoutingDeviceCell, routeReconciler.Cell, bandwidth.Cell. Plus cell.Provide stubs: device/route/L2announce tables, disabled wireguard config+agent, disabled ipsec config, fakeipsec.Agent, fake sysctl, bigtcp.Config/Features (fake), connector.Config (fake), gneigh config (fake), fakenode.Handler (subscribed to node manager), newStubAPIHandlers, newEndpointDatapathDeps, newMapStubs. Has stub types: `disabledWireguardConfig`, `disabledWireguardAgent`, `disabledIPsecConfig`.
- `pkg/datapath/loader/loader_windows.go` — Added `NewCompilationLock()` (via lock.RWMutex) and a full `stubLoader` implementing all 9 `loaderTypes.Loader` methods (returns errNotSupported / closed channels; no panics). Also has FilterSetter, LoadSockTerm, DeviceHasSKBProgramLoaded stubs from prior session.
- `pkg/datapath/linux/bandwidth/bandwidth_windows.go` — Fixed Module description (removed parentheses).
- `pkg/maps/subnet/cell.go` — Added `//go:build linux` tag.

Work completed:
- [x] Windows binary runs `--help` (hive init completes)
- [x] Resolved ~20 layers of missing hive DI types
- [ ] `ciliumd.exe hive` graph FULLY populates — IN PROGRESS (subnet.Cell just wired, not rebuilt)
- [ ] Agent actually starts (OnStart hooks) — not yet reached
- [ ] Real hnslib/cncshim/hcsshim implementations — not started
</work_done>

<technical_details>
- **Validation loop**: `$env:GOOS='windows'; $env:GOARCH='amd64'; go build -o $env:TEMP\ciliumd.exe ./daemon` then `& $env:TEMP\ciliumd.exe hive 2>&1 | Select-Object -Last 22`. The `hive` subcommand populates the FULL DI graph and reports the FIRST missing type (dig chain shown bottom-up). Env vars don't persist across powershell calls.
- **Linux build check**: `go build -o $env:TEMP\ciliumd_linux ./daemon` (must use `-o` on GOOS=linux since `./daemon` collides with the daemon/ directory). **NOT re-verified this session** — must confirm Linux still builds before considering done.
- **`pkg/datapath/fake/cells.go` is the goldmine reference** — it wires ALL fake datapath providers used in tests. The Windows cell mirrors its provider list (fakeloader, fakeiptables, fakebandwidth, fakeipsec, fakesignalmap, fakeauthmap, fakeencrypt, fakebigtcp, fakegneigh, fakeconnector, fakenode, fakesysctl). These fakes are pure-Go with NO build tags and portable imports, so they build on Windows.
- **Key architectural insight**: Since `pkg/endpoint` (and the whole daemon) already compiles on Windows, ALL the TYPE packages (ctmap, policymap, lxcmap, iptables, bandwidth, loader/types, tunnel, bigtcp, subnet) build on Windows — only their BPF-backed Cell CONSTRUCTORS/reconcilers are Linux-only. So providing `nil` or fakes for the interface types works.
- **statedb tables auto-register**: `statedb.NewTable(db,...)` (called by `tables.NewDeviceTable` etc.) registers with the DB internally (`NewTableAny` returns `table, db.registerTable(table)`). `db.RegisterTable` is UNEXPORTED — do NOT call it. Just `cell.Provide` the RWTable and downcast to read-only Table.
- **Cells already cross-platform** (have `_linux.go`/`_unspecified.go` splits or pure-statedb, build on Windows without changes): link.Cell, routeReconciler.Cell (route/reconciler), xdp.Cell, tunnel.Cell, ipset.Cell, mtu.Cell, monitorAgent.Cell, tables.NodeAddressCell, dpnode.AddressingCell, tables.DirectRoutingDeviceCell, neighbor.Cell (via cell_windows.go from prior session).
- **subnet map split rationale**: `newSubnetMap` opens a BPF map in an OnStart hook (would fail on Windows without eBPF-for-Windows runtime), so cell.go was tagged linux and cell_windows.go provides only the StateDB table. `subnet.go`/`cmds.go`/`table.go` remain untagged (compile on Windows fine — cilium/ebpf supports Windows).
- **hive allows unused provides** — constructors are lazy, only invoked if consumed. So batching extra fake providers (e.g. maps_windows.go egress/nat nils) is safe.
- **fakenode.Handler** implements both `node.Handler` and `node.IDHandler`; provided together and subscribed via `nodeManager.Subscribe(h)` mirroring fake/cells.go.
- **stubLoader vs fakeloader**: fakeloader.Loader PANICS ("implement me") on CompileOrLoad/ReloadDatapath. I wrote a clean `stubLoader` in loader_windows.go returning errNotSupported instead, to avoid runtime panics if endpoint regeneration is attempted.
- **Runtime warning seen (harmless)**: `Running Cilium with "kvstore"="" requires identity allocation via CRDs. Changing identity-allocation-mode to "crd"` — expected during hive populate.
- **git commit trailers required**: `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` and `Copilot-Session: 4eff9d43-adcd-4986-9abb-854dbdbd7d0a`. **Nothing has been committed this session yet** — all changes are uncommitted.
</technical_details>

<important_files>
- `pkg/datapath/cells_windows.go`
   - THE central Windows datapath assembly. `//go:build !linux`. Mirrors the Linux `cells.go` but with cross-platform cells + disabled/fake stubs. This is where nearly all missing-type resolutions were added. Continue adding providers here as `hive` reveals more.
- `pkg/datapath/endpoint_datapath_windows.go`
   - Provides the endpoint-construction datapath deps (Loader, Orchestrator, iptables, ctmap GC, etc.) via `endpointDatapathDepsOut` struct with `cell.Out`.
- `pkg/datapath/maps_windows.go`
   - Provides fake/nil BPF maps (signalmap, authmap, encrypt, egress, nat) via `mapStubsOut` with `cell.Out`.
- `pkg/datapath/api_handlers_windows.go`
   - Stub REST API handlers (BPF-backed on Linux) returning HTTP 501, keeping the API server graph complete.
- `pkg/datapath/loader/loader_windows.go`
   - `//go:build !linux`. Has `NewCompilationLock()`, `stubLoader` (9-method Loader impl, no panics), FilterSetter, LoadSockTerm, DeviceHasSKBProgramLoaded. All datapath-affecting ops return errNotSupported or no-op.
- `pkg/maps/subnet/cell.go` + `cell_windows.go`
   - cell.go tagged `//go:build linux` (BPF map + reconciler). cell_windows.go provides only the StateDB table for the cross-platform subnet watcher.
- `pkg/datapath/linux/bandwidth/bandwidth_windows.go`
   - Disabled bandwidth Manager + Cell. Module description fixed (no parentheses — hive regex).
- `pkg/datapath/fake/cells.go` (reference only, do NOT edit)
   - The canonical list of fake datapath providers; consult it whenever a new datapath type is missing.
</important_files>

<next_steps>
Immediate next step:
- Rebuild and re-run `hive` after wiring subnet.Cell: `$env:GOOS='windows'; $env:GOARCH='amd64'; go build -o $env:TEMP\ciliumd.exe ./daemon; & $env:TEMP\ciliumd.exe hive 2>&1 | Select-Object -Last 22`. Continue resolving missing types (consult `pkg/datapath/fake/cells.go` for the right fake) until `hive` populates the full graph with exit 0.

Then:
- **Verify Linux still builds**: `go build -o $env:TEMP\ciliumd_linux ./daemon` on GOOS=linux (NOT done this session — critical to confirm none of the subnet.Cell/other splits broke Linux).
- **Commit** the accumulated changes with the required trailers (nothing committed yet this session).
- **Test actual startup**: once `hive` validates, try running the agent (a minimal start) to see which OnStart lifecycle hooks fail on Windows (e.g. BPF map creation, netlink calls, /proc access). Make those no-op-on-start vs error as needed.

Later phases (large, not started):
- Real Windows implementations via cncshim (ebpf map updates), hnslib (network/namespace/policy/endpoint), hcsshim (containers), replacing the disabled stubs where functionality is actually needed.

Verification discipline: after every change rebuild BOTH GOOS=windows AND GOOS=linux; never break Linux. Commit iteratively.
</next_steps>
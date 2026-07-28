<overview>
The user wants to make `cilium-agent` build and run on Windows nodes while preserving Linux functionality. The strategy: separate Linux-specific code from platform-neutral code using Go build tags (`_linux.go`/`_windows.go`/`_unspecified.go` files), providing Windows implementations (best-effort via public libs like cncshim/hnslib/hcsshim) or dummy/error stubs where real functionality isn't feasible yet. The current phase focuses on getting the daemon to **compile** for `GOOS=windows`; the user explicitly chose a **datapath-boundary split** strategy and a **compile-only stub Map** for `pkg/bpf`. The end goal is a buildable+runnable Windows agent, acknowledged as a large multi-stage effort.
</overview>

<history>
1. **Continued from prior summary** — the porting was mid-flight. Prior work (commits `2fe255022a`, and pre-compaction) had split ~15 leaf packages and vendored shims.

2. **Fixed hostfirewallbypass, xdp, common/ipsec** (committed as `b4324c7c15`):
   - Split `setProxyEgressMark` (uses unix.SetsockoptUint64/SOL_SOCKET/SO_MARK) into `bypass_linux.go` (real) + `bypass_unspecified.go` (no-op).
   - Moved `Config.GetAttachFlags()` (uses `link.XDPAttachFlags`) into `xdp_linux.go`; it's unused outside the package on Windows.
   - Tagged `common/ipsec/utils.go` + `utils_test.go` `//go:build linux` (XFRM-only; consumed only by Linux ipsec package).

3. **Hit the datapath core wall** — `GOOS=windows go build ./daemon` revealed daemon imports `pkg/datapath.Cell` (~40 subpackage cells) and pulls `pkg/datapath/linux` transitively via `pkg/proxy`. Measured 79+ non-test packages importing ebpf/netlink directly.

4. **Asked user for strategy** — user chose: "Datapath-boundary split: create cells_linux.go/cells_windows.go and a minimal Windows datapath cell, tag the ~79 BPF packages linux-only, and split the few cross-platform consumers." Stored as a repository memory.

5. **Executed datapath-boundary split** (committed as `1d041f7098`):
   - Split `pkg/proxy/cell.go`: extracted `linuxdatapath.NodeEnsureLocalRoutingRule()` into `nodeEnsureLocalRoutingRule()` helper in `cell_linux.go`/`cell_unspecified.go`; removed the `linuxdatapath` import.
   - Tagged `pkg/datapath/cells.go` `//go:build linux`; created minimal `cells_windows.go` with a bare `Cell` module.

6. **Tackled probes (foundational for pkg/bpf)** (committed as `8f9ac29d96`):
   - Discovered `pkg/bpf` → `datapath/config` → `probes`. Tagged `probes.go`, `attach_cgroup.go`, `attach_type.go`, `managed_neighbors.go`, `kernel_hz.go` `//go:build linux`.
   - Created `probes_stub_unspecified.go` (`!linux`) stubbing all 28 externally-referenced symbols returning `ErrNotSupported`. probes now compiles on Windows; unblocked `datapath/config`.

7. **Made pkg/bpf compile on Windows** (committed as `a2fe48f6d4`) — major milestone:
   - Copied `map_linux.go` (1673 lines) → `map_windows.go` with `!linux` tag; nearly all compiled (cilium/ebpf has Windows support).
   - Created Windows helper files: `stats_windows.go` (copy), `map_register_windows.go` (copy), `bpffs_windows.go` (stubs), `bpf_windows.go` (createMap real, OpenOrCreateMap ignores pinning, GetMtime via Go clock).
   - Added `vendor/golang.org/x/sys/unix/cilium_errno_windows.go` with `ENOSPC`, `ENOENT` as `syscall.Errno`.
   - Verified Linux still builds pkg/bpf.

8. **Advanced the daemon frontier** (committed as `01b5c2b5f6`):
   - Split `daemon/cmd/daemon.go`: extracted `ipsec.ProbeXfrmStateOutputMask()` into `probeXfrmStateOutputMask()` in `ipsec_linux.go`/`ipsec_unspecified.go`; removed `pkg/datapath/linux/ipsec` import.
   - Copied `pkg/bpf/ops_linux.go` → `ops_windows.go` (platform-neutral; adds `NewMapOps`/`StructBinaryMarshaler` on Windows).
   - Removed `//go:build linux` from `pkg/maps/netdev/netdev_sync.go` (content is platform-neutral).
   - Split `pkg/datapath/linux/utime/utime.go`: moved `getBoottime()` into `utime_linux.go` (real, uses unix clocks) + `utime_unspecified.go` (returns `time.Now()`).

9. **Asked user about pkg/bpf Map approach** — user chose "Generate a Windows stub Map (compile-only)".

10. **Currently splitting route/reconciler** (NOT yet committed) — needed by `pkg/proxy` (cross-platform via `routes.go`). Tagged `reconciler.go` `//go:build linux`; created `reconciler_windows.go` with a no-op `noopOps` implementing reconciler.Operations+BatchOperations, keeping the cross-platform `statedb/reconciler.Register`.
</history>

<work_done>
Files created (this session):
- `pkg/k8s/hostfirewallbypass/bypass_linux.go` + `bypass_unspecified.go`
- `pkg/datapath/xdp/xdp_linux.go`
- `pkg/proxy/cell_linux.go` + `cell_unspecified.go`
- `pkg/datapath/cells_windows.go` (minimal `Cell` module, `!linux`)
- `pkg/datapath/linux/probes/probes_stub_unspecified.go` (28-symbol stub)
- `pkg/bpf/map_windows.go` (copy of map_linux.go, `!linux`)
- `pkg/bpf/stats_windows.go`, `map_register_windows.go`, `bpffs_windows.go`, `bpf_windows.go`, `ops_windows.go`
- `vendor/golang.org/x/sys/unix/cilium_errno_windows.go` (ENOSPC, ENOENT)
- `daemon/cmd/ipsec_linux.go` + `ipsec_unspecified.go`
- `pkg/datapath/linux/utime/utime_linux.go` + `utime_unspecified.go`
- `pkg/datapath/linux/route/reconciler/reconciler_windows.go` (UNCOMMITTED)

Files modified:
- `pkg/k8s/hostfirewallbypass/bypass.go` (removed unix/linux_defaults/identity imports + setProxyEgressMark)
- `pkg/datapath/xdp/xdp.go` (removed link import + GetAttachFlags)
- `pkg/common/ipsec/utils.go` + `utils_test.go` (added `//go:build linux`)
- `pkg/proxy/cell.go` (removed linuxdatapath import, call nodeEnsureLocalRoutingRule)
- `pkg/datapath/cells.go` (added `//go:build linux`)
- `pkg/datapath/linux/probes/{probes,attach_cgroup,attach_type,managed_neighbors,kernel_hz}.go` (added `//go:build linux`)
- `daemon/cmd/daemon.go` (removed ipsec import, call probeXfrmStateOutputMask)
- `pkg/maps/netdev/netdev_sync.go` (removed `//go:build linux`)
- `pkg/datapath/linux/utime/utime.go` (removed getBoottime + bufio/os/runtime/unix imports + nClockSamples const)
- `pkg/datapath/linux/route/reconciler/reconciler.go` (added `//go:build linux`)

Commits this session: `b4324c7c15`, `1d041f7098`, `8f9ac29d96`, `a2fe48f6d4`, `01b5c2b5f6` (5 commits). All on branch `ppereira-linux-windows-separation`.

Work completed:
- [x] pkg/bpf compiles on Windows (major milestone) + Linux still builds
- [x] probes, datapath/config, netdev, utime compile on Windows
- [x] datapath.Cell + proxy boundary split
- [ ] route/reconciler split — files edited, NOT committed, NOT yet build-verified
- [ ] Remaining frontier: signalmap, monitor/agent (perf), bandwidth, routing, socketlb, connector
</work_done>

<technical_details>
- **Build loop**: `$env:GOOS='windows'; $env:GOARCH='amd64'; go build ./daemon 2>&1` — reveals one frontier layer at a time. Env vars DON'T persist across powershell calls; set per-command.
- **cilium/ebpf HAS Windows support** — `pkg/bpf`'s core (ebpf.Map, NewMapWithOptions) compiles on Windows. The blockers were Linux-only helper files (bpffs, map_register, stats) + `unix.*` constants, not the ebpf lib itself. Copying `map_linux.go`→`map_windows.go` and fixing ~6 undefined symbols was faster than hand-writing stubs.
- **Convention**: `*_linux.go` (real, `//go:build linux` OR implicit via filename) + `*_unspecified.go` (`//go:build !linux`, covers darwin too) or `*_windows.go` (`//go:build windows` OR `!linux`). Filename `_linux.go` forces GOOS=linux even without an explicit tag — so to make such a file cross-platform you must copy/rename, not just edit the tag.
- **Chosen architecture** (stored as memory): datapath-boundary split — `pkg/datapath.Cell` splits linux/windows; ~79 BPF/netlink packages tagged linux-only rather than per-package stubbed.
- **route/reconciler split insight**: `statedb/reconciler.Register` is cross-platform (pure Go); only the `ops` struct's netlink calls (RouteReplace/RouteDel/RouteListFiltered) are Linux. So Windows keeps Register with a `noopOps` that satisfies Operations+BatchOperations. `cell.go` does `cell.Provide(registerReconciler)` + `cell.Invoke(desiredRouteRefresher)`; refresher.go/manager.go/table.go/types.go are cross-platform (no netlink). Only `reconciler.go` imported netlink/nl.
- **reconciler.Operations interface signatures**: Update/Delete(ctx, statedb.ReadTxn, statedb.Revision, *DesiredRoute) error; Prune(ctx, ReadTxn, iter.Seq2[*DesiredRoute, statedb.Revision]) error; BatchOperations: UpdateBatch/DeleteBatch(ctx, ReadTxn, []reconciler.BatchEntry[*DesiredRoute]).
- **pkg/proxy is cross-platform** and uses `route/reconciler` heavily in `routes.go` (DesiredRoute, DesiredRouteManager, RouteOwner, Scope, RTN_LOCAL, AdminDistanceDefault) + `netlink.SCOPE_LINK` (shimmed). It only used `linuxdatapath.NodeEnsureLocalRoutingRule` from datapath/linux.
- **Remaining frontier packages need FULL splits** (netlink/link functions can't be shimmed trivially): connector (link.AddAltName, netlink.LinkAdd, netlink.Netkit/Veth, LinkSetGRO*), socketlb (link.RawAttachProgram/QueryPrograms/RawDetachProgram), routing (netlink.RuleDel/RouteReplace, unix.RTN_UNREACHABLE/IFF_SLAVE), bandwidth (netlink.QdiscReplace, netlink.Fq, Manager+FqDefault* in linux files), reconciler (done). perf-based: signalmap + monitor/agent use `cilium/ebpf/perf` (perf.Record/Reader/NewReader/IsUnknownEvent) which is empty on Windows; also monitor/agent uses `unix.EBADFD`.
- **Missing unix constants across frontier** (candidates for shim): EBADFD, ENOLINK, EPERM, EINVAL, EBADF (errnos), RTN_UNREACHABLE(7), IFF_SLAVE(0x800), IFNAMSIZ(16). BUT packages using netlink/link FUNCTIONS need full splits anyway, so shimming unix constants for those is wasted — decide per-package.
- **nl.FAMILY_V4/V6**: `github.com/vishvananda/netlink/nl` subpackage — FAMILY constants only in nl's linux files; a separate `!linux` shim would be needed there (main netlink package already has a `netlink_constants_others.go` shim from prior work).
- **git commit trailers**: include `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` and `Copilot-Session: 4eff9d43-adcd-4986-9abb-854dbdbd7d0a`.
</technical_details>

<important_files>
- `pkg/bpf/map_windows.go`
   - Foundational — the copied Map abstraction that makes pkg/bpf compile on Windows. `!linux` tag. Only used `unix.ENOSPC`/`unix.ENOENT` beyond what compiled.
- `pkg/bpf/bpffs_windows.go`, `bpf_windows.go`, `stats_windows.go`, `map_register_windows.go`, `ops_windows.go`
   - Windows counterparts of Linux-only bpf helper files. Provide BPFFSRoot/TCGlobalsPath/MapPath/MkdirBPF/CheckOrMountFS (stubs), createMap/OpenOrCreateMap/GetMtime, DumpStats, registerMap/GetMap/GetOpenMaps, NewMapOps/StructBinaryMarshaler.
- `pkg/datapath/linux/probes/probes_stub_unspecified.go`
   - Stubs 28 probe symbols (Have*, KernelHZ, Jiffies, CreateHeaderFiles, ExecuteHeaderProbes, FeatureProbes/ProgramHelper types) returning ErrNotSupported. Unblocks pkg/bpf.
- `pkg/datapath/cells.go` + `cells_windows.go`
   - The datapath boundary. cells.go is `//go:build linux` (the ~40-cell wiring); cells_windows.go is a minimal `Cell` module. External API used: DevicesControllerCell, BackendNeighborSyncCell, NewNodeHandler, CheckRequirements, NodeEnsureLocalRoutingRule.
- `pkg/datapath/linux/route/reconciler/reconciler_windows.go` (UNCOMMITTED, needs build verification)
   - Windows no-op reconciler. `registerReconciler` returns a `noopOps`-backed reconciler via cross-platform `reconciler.Register`. Needed because pkg/proxy (cross-platform) imports this package.
- `vendor/golang.org/x/sys/unix/cilium_errno_windows.go`
   - `!`windows shim for Linux errnos. Currently ENOSPC(0x1c), ENOENT(0x2). Likely to grow (EBADF, EINVAL, EPERM, ENOLINK, EBADFD).
- `daemon/cmd/daemon.go` + `ipsec_linux.go`/`ipsec_unspecified.go`
   - daemon/cmd is the huge core package; directly imports ~14 Linux/BPF packages (pkg/bpf, maps/ctmap, maps/lxcmap, maps/nat, maps/neighborsmap, maps/ratelimitmap, maps/ipmasq, maps/iptrace, maps/metricsmap, maps/nat/stats, ipsec, ipsec/types, probes, safenetlink). Each may need extraction/splitting as the frontier advances.
</important_files>

<next_steps>
Immediate next step:
- Build-verify the route/reconciler split: `$env:GOOS='windows'; $env:GOARCH='amd64'; go build ./pkg/datapath/linux/route/reconciler` AND `go build ./pkg/proxy`; also verify Linux: `$env:GOOS='linux'; go build ./pkg/datapath/linux/route/reconciler`. Fix any interface-signature mismatches in `reconciler_windows.go` (verify reconciler.Operations/BatchOperations exact signatures if it fails). Then commit.

Remaining frontier packages (fix + rebuild `./daemon` + commit iteratively):
- `pkg/datapath/linux/bandwidth` — Manager + FqDefault* live in linux files; ops.go uses netlink.QdiscReplace/Fq. Split ops/manager linux + windows stub.
- `pkg/datapath/linux/routing` — netlink.RuleDel/RouteReplace, unix.RTN_UNREACHABLE/IFF_SLAVE. Full split.
- `pkg/socketlb` — link.RawAttachProgram/QueryPrograms/RawDetachProgram + unix errnos. Full split.
- `pkg/datapath/connector` — netlink.LinkAdd/Netkit/Veth, link.AddAltName. Full split (large).
- `pkg/maps/signalmap` — perf.Record/NewReader. Split cell.go/signalmap.go (has a fake/ subpackage; check it).
- `pkg/monitor/agent` — perf.Reader/NewReader/IsUnknownEvent + unix.EBADFD. Split.

Approach: For each, grep which files import netlink/link/perf/unix (only those need splitting), tag those `//go:build linux`, create `_windows.go` stubs returning errUnsupported / no-ops, preserving the exported API the cross-platform consumers need. Rebuild `./daemon` after each to track the shrinking frontier. Add unix constants to `cilium_errno_windows.go` only where a package is otherwise cross-platform. After the frontier clears (daemon compiles), the next phase is hive-start stubs so the agent actually starts, then real hnslib/cncshim/hcsshim implementations (a much larger, later effort). Verify Linux build is never broken after each batch. Clean up any temp files before commits.
</next_steps>
<overview>
The user wants to make `cilium-agent` build and run on Windows nodes while preserving Linux functionality. The strategy: separate Linux-specific code from platform-neutral code using Go build tags (`_linux.go`/`_windows.go`/`_unspecified.go` files), providing Windows implementations (best-effort via public libs like cncshim/hnslib/hcsshim) or dummy/error stubs where real functionality isn't feasible. **MILESTONE ACHIEVED this session**: the `./daemon` (cilium-agent) now compiles for both `GOOS=linux` AND `GOOS=windows`, producing a 178 MB `ciliumd.exe`. The remaining goal is making it **runnable** on Windows (hive-start stubs, then real hnslib/cncshim implementations).
</overview>

<history>
1. **Continued mid-flight from prior summary** — porting was underway on branch `ppereira-linux-windows-separation`. The route/reconciler split (`reconciler_windows.go`) was uncommitted and unverified.
   - Build-verified route/reconciler on Windows AND Linux; committed as `ca617af7af`.

2. **Iteratively advanced the daemon compile frontier** — repeated loop: `GOOS=windows go build ./daemon` → identify failing packages → split each → verify Linux unbroken → commit → rebuild daemon. The frontier shrank across these batches:
   - **Batch 1 (perf packages)**: signalmap, monitor/agent, bandwidth. Discovered `cilium/ebpf/perf` is empty on Windows (`reader.go`/`ring.go` are `//go:build !windows`). Created a Windows perf stub. Committed `ffbd632488`.
   - **Batch 2 (netlink packages)**: socketlb, routing, neighbor, connector. Discovered `vishvananda/netlink`, `safenetlink`, `sysctl`, `netns`, `ebpf/link` ALL compile on Windows (prior shim work). connector needed only `unix.IFNAMSIZ`. Committed `a5a6f941dc`.
   - **Batch 3**: mtu, monitor, endpoint. bandwidth Windows stub, endpoint directory-exchange split, neutralized a misnamed monitor/api file. Committed `938c1bb5cf`.
   - **Batch 4**: ipam, ztunnel/zds, envoy, fqdn/dnsproxy, hubble/cell. Socket-behavior splits (setsockopt, SCM_RIGHTS, unix listener). Committed `6a1d8f2dbb`.
   - **Batch 5 (loader)**: datapath/loader — tagged all 23 files linux, wrote one Windows stub. Committed `aeefc796ca`.
   - **Batch 6**: datapath/sockets (socket-diag split), infraendpoints netdev stub. Committed `5348473f9c`.
   - **Batch 7**: loadbalancer/reconciler (constants only), daemon/healthz sockopt split. **Daemon compiled on Windows.** Committed `eb94f2e137`.

3. **Verified the milestone** — confirmed both `GOOS=windows` (→ `ciliumd.exe`, 178.5 MB) and `GOOS=linux` daemon builds succeed. Stored two repository memories about the milestone and the split convention.
</history>

<work_done>
Files created this session:
- `pkg/datapath/linux/route/reconciler/reconciler_windows.go` (verified + committed)
- `vendor/github.com/cilium/ebpf/perf/reader_windows.go` (Windows perf stub: Record, Reader, NewReader, IsUnknownEvent, etc.)
- `pkg/socketlb/cgroup_windows.go` (attachCgroup/detachCgroup stubs)
- `pkg/datapath/linux/routing/routing_windows.go` (Configure/ReconcileGatewayRoutes/Delete stubs)
- `pkg/datapath/neighbor/cell_windows.go` (minimal Cell without netlink reconciler)
- `pkg/datapath/linux/bandwidth/bandwidth_windows.go` (disabled Manager, consts, GetBytesPerSec, Cell)
- `pkg/endpoint/directory_linux.go` + `directory_windows.go` (exchangeDirectories: Renameat2 vs os.Rename fallback)
- `pkg/ztunnel/zds/server_linux.go` + `server_windows.go` (socketControlRights: UnixRights vs nil)
- `pkg/fqdn/dnsproxy/proxy_setsockopt_linux.go` + `proxy_setsockopt_windows.go` (setSoMarks)
- `pkg/fqdn/dnsproxy/noop_sessionudpfactory_linux.go` + `_windows.go` (ReadRequest: nil vs dns.SessionUDP{})
- `pkg/fqdn/dnsproxy/udp_windows.go` (NewSessionUDPFactory + listenConfig stubs)
- `pkg/hubble/server/serveroption/option_unspecified.go` (WithUnixSocketListener via os.Remove)
- `pkg/datapath/loader/loader_windows.go` (FilterSetter, LoadSockTerm, DeviceHasSKBProgramLoaded stubs)
- `pkg/datapath/sockets/sockets_windows.go` (SocketDestroyer/SocketFilter/NewSocketDestroyer/InetDiagDestroyEnabled/StateFilter stubs)
- `daemon/infraendpoints/netdev_windows.go` (getCiliumHostIPsFromNetDev stub)
- `daemon/healthz/sockopt_windows.go` (setsockoptReuseAddrAndPort no-op)

Files renamed (git mv, content was platform-neutral but filename-locked):
- `pkg/monitor/api/monitor_event_interface_linux.go` → `monitor_event_interface.go`
- `daemon/healthz/sockopt.go` → `sockopt_linux.go`

Files modified (added `//go:build linux` or edited):
- `pkg/datapath/linux/bandwidth/ops.go` (added linux tag)
- `pkg/datapath/neighbor/cell.go`, `desired_neighbor_calculator.go`, `neighbor_reconciler.go` (added linux tag)
- `pkg/socketlb/cgroup.go`, `pkg/datapath/linux/routing/routing.go`, `pkg/fqdn/dnsproxy/udp.go`, `pkg/datapath/sockets/{probe,sockets}.go` (added linux tag)
- All 23 `pkg/datapath/loader/*.go` (added linux tag)
- `pkg/ztunnel/zds/server.go` (call socketControlRights)
- `pkg/fqdn/dnsproxy/proxy.go` (removed setSoMarks + unix import; call helpers)
- `pkg/fqdn/dnsproxy/noop_sessionudpfactory.go` (removed ReadRequest)
- `pkg/endpoint/directory.go` (removed unix import + inline Renameat2; call exchangeDirectories)
- `vendor/golang.org/x/sys/unix/cilium_errno_windows.go` (grew substantially — see below)

Work completed:
- [x] cilium-agent daemon compiles for GOOS=windows (MAJOR MILESTONE)
- [x] cilium-agent daemon still compiles for GOOS=linux (verified)
- [x] Windows binary produces ciliumd.exe (178.5 MB)
- [ ] Runtime: agent does not yet actually START on Windows (untested/unimplemented)
- [ ] Real Windows implementations (hnslib/cncshim/hcsshim) — not started
</work_done>

<technical_details>
- **Build loop**: `$env:GOOS='windows'; $env:GOARCH='amd64'; go build ./daemon 2>&1 | Select-String -Pattern '^#'` lists failing packages one layer at a time. Env vars do NOT persist across powershell calls — set per-command.
- **Linux daemon build gotcha**: `go build ./daemon` on GOOS=linux FAILS with "build output 'daemon' already exists and is a directory" — must use `go build -o $env:TEMP\ciliumd_linux ./daemon`. On Windows the output is `.exe` so no collision, but use `-o` for a real binary check.
- **cilium/ebpf HAS Windows support** — ebpf.Map/link/etc. compile. Only `cilium/ebpf/perf` is empty on Windows (perf ring-buffer is Linux-only). Perf symbols used repo-wide: only `Record`, `Reader`, `NewReader`, `IsUnknownEvent` — all stubbed in `reader_windows.go`.
- **vishvananda/netlink COMPILES on Windows** (prior shim work: `netlink_constants_others.go`). So Windows stubs CAN reference `netlink.Link`, `netlink.Route`, `netlink.SocketID`, etc. `nl.NetlinkSocket` (the `nl` subpackage) does NOT. `safenetlink`, `sysctl`, `netns`, `ebpf/link` all compile on Windows too.
- **Convention**: real code in `*_linux.go` (`//go:build linux`); stubs in `*_windows.go`/`*_unspecified.go` (`//go:build !linux`). Filename `_linux.go` forces GOOS=linux even without an explicit tag — to make such content cross-platform you must RENAME (git mv), not just add a tag.
- **Strategy: shim constants, split behaviors.** Pure integer/errno constants (RT_TABLE_MAIN, IFF_SLAVE, IPPROTO_*, MSG_TRUNC, EADDRNOTAVAIL, etc.) go into the vendored unix shim. Behavioral syscalls (SetsockoptInt, Renameat2, UnixRights) are split into `_linux`/`_windows` helper functions at the call site — NOT faked in the shim.
- **`cilium_errno_windows.go` now contains**: `type Errno = syscall.Errno`; errnos ENOSPC, ENOENT, EBADFD, EBADF, EINVAL, EPERM, ENOLINK, ESRCH, EEXIST, E2BIG, EOPNOTSUPP, EADDRNOTAVAIL; constants IFNAMSIZ, RTNH_F_DEAD, RTNH_F_LINKDOWN, RT_TABLE_MAIN, RTN_UNREACHABLE, MSG_TRUNC, IFF_SLAVE, IPPROTO_TCP, IPPROTO_UDP.
- **cilium/dns SessionUDP differs by platform**: interface on Linux (`udp.go`), struct on Windows (`udp_windows.go`). So a no-op factory must return `nil` on Linux but `dns.SessionUDP{}` on Windows — hence the `_linux`/`_windows` split of ReadRequest.
- **loader wholesale approach**: 23 files, 13 kernel-bound. Rather than split each, tagged ALL 23 `//go:build linux` and wrote one `loader_windows.go` exposing only the 3 externally-used symbols (FilterSetter, LoadSockTerm, DeviceHasSKBProgramLoaded). loader.Cell is only used by cells.go (already linux-tagged), so not needed on Windows.
- **Import-path gotchas**: dnsproxy ipfamily is `pkg/fqdn/proxy/ipfamily` (not `pkg/ipfamily`); `bandwidth.Config` in external files is an alias-import of `bandwidth/types`, a red herring (not the root package).
- **Windows supports AF_UNIX** — `net.Listen("unix", ...)` works; only `unix.Unlink` needed replacing with `os.Remove`. `os.Getuid()` returns -1 on Windows (compiles, and the uid==0 branch is safely skipped).
- **git commit trailers**: include `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` and `Copilot-Session: 4eff9d43-adcd-4986-9abb-854dbdbd7d0a`.
</technical_details>

<important_files>
- `vendor/golang.org/x/sys/unix/cilium_errno_windows.go`
   - The single Windows shim for all Linux errnos/constants referenced at compile time. `//go:build windows`. Grows whenever a cross-platform package references a new `unix.X` constant. Contains `type Errno = syscall.Errno` alias.
- `vendor/github.com/cilium/ebpf/perf/reader_windows.go`
   - Windows stub for the perf package (empty on Windows). Unblocks signalmap, monitor/agent, pkg/signal. `//go:build windows`.
- `pkg/datapath/loader/loader_windows.go` + all 23 `loader/*.go` tagged linux
   - loader is the core Linux BPF program loader (tc/tcx/xdp/netkit/qdisc). Wholesale linux-tagged; Windows stub exposes FilterSetter, LoadSockTerm, DeviceHasSKBProgramLoaded returning errNotSupported.
- `pkg/datapath/linux/bandwidth/bandwidth_windows.go`
   - Provides a disabled Manager + consts + Cell so cross-platform consumers (endpoint, endpointmanager) build. bandwidth.go/cell.go/ops.go are all linux-tagged.
- `pkg/datapath/neighbor/cell_windows.go`
   - Minimal neighbor Cell keeping the neutral tables/config but dropping netlink reconciler/calculator wiring. cell.go + the 2 netlink files are linux-tagged.
- `pkg/fqdn/dnsproxy/` (udp.go linux-tagged; udp_windows.go, proxy_setsockopt_*, noop_sessionudpfactory_*)
   - Transparent DNS proxy — heavy Linux socket code (raw sockets, cmsg, setsockopt, SessionUDP). Windows stubs return no-op factory/listenConfig.
- `daemon/cmd/*` (the huge core daemon package)
   - Assembled the whole hive; now compiles on Windows. Prior splits: `ipsec_linux.go`/`ipsec_unspecified.go`, `daemon.go`.
</important_files>

<next_steps>
The compile milestone is complete for `./daemon`. Remaining work toward "runnable on Windows":

Immediate next steps:
- **Test runnability**: run the Windows `ciliumd.exe` (e.g., `--help`, `version`, or a minimal start) to see how far the hive gets before failing on a stubbed component. Since the session runs ON Windows, the binary can be executed directly. Determine the daemon's CLI entrypoint/subcommands.
- Identify which hive cells fail at start (OnStart hooks calling stubbed functions that return ErrNotSupported) and decide whether to make them no-op-on-start vs. error.

Later phases (large efforts, not started):
- Hive-start stubs so the agent process actually initializes on Windows without crashing.
- Real Windows implementations using the user's specified libraries: cncshim (ebpf map updates), hnslib (network/namespace/policy/endpoint operations), hcsshim (container operations).
- Build/verify other cilium binaries if needed (the task focused on cilium-agent/daemon).

Verification discipline: after every change, rebuild BOTH `GOOS=windows go build ./daemon` and `GOOS=linux go build -o $env:TEMP\x ./daemon`; never break Linux. Commit iteratively with the required trailers.
</next_steps>
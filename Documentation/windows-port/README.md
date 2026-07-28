# Porting cilium-agent to Windows

This document records the goal, strategy, and work done to make the
`cilium-agent` (the `./daemon` binary) **build and run on Windows nodes** while
preserving full Linux functionality. It also serves as a starting point for the
remaining (native datapath) work.

## Original task & strategy

> Make the cilium-agent build and run for Windows nodes.
>
> Cilium agent porting can be managed using the following strategies:
>
> - Use <https://github.com/princepereira/cncshim/> for eBPF map updates.
> - Use <https://github.com/microsoft/hnslib> for network components (network,
>   namespace, policy, endpoint) operations that on Linux are done via netlink.
> - If there are any container-related operations, use
>   <https://github.com/microsoft/hcsshim> if it makes sense.
> - Any operations which cannot be achieved using the above libraries: use
>   abstract functions split across `*_linux.go` / `*_windows.go` files. If the
>   Windows side can have a real implementation using a public, secure library,
>   implement it. If a dummy/no-op implementation is acceptable, keep it as a
>   stub.
>
> Finally, the cilium-agent should be buildable and runnable on Windows as well
> as Linux, each with its own platform-specific implementation.

### Guiding principles

- **Real code stays Linux-tagged.** Linux behavior must never regress.
- **Build-tag separation** is the primary mechanism:
  `foo_linux.go` (`//go:build linux`), `foo_windows.go` (`//go:build windows`),
  `foo_other.go` / `foo_unspecified.go` (`//go:build !linux`).
- **Best-effort Windows implementations** where a portable/public library
  exists (e.g. the standard `net` package, `golang.org/x/sys/windows`);
  **dummy stubs** where BPF/netlink semantics cannot be reproduced yet.
- **Verify both platforms build after every change**, and iteratively run the
  Windows agent to find the next startup blocker.

## Current status

- ✅ `cilium-agent` **builds** for `GOOS=windows` and `GOOS=linux`.
- ✅ The full hive dependency-injection graph populates on Windows.
- ✅ The agent **starts and stays running** on Windows: it creates the host
  endpoint, serves the Cilium API / health API / shell socket, and runs its
  control loops without crashing.
- ⏳ Native datapath programming (policy-map programming, BPF program loading,
  HNS/cncshim wiring) is stubbed/no-op and is the next major phase.

## Build & run

Build (from repo root — `-o` is required because `./daemon` collides with the
`daemon/` directory):

```powershell
# Windows
$env:GOOS='windows'; $env:GOARCH='amd64'; go build -o $env:TEMP\ciliumd.exe ./daemon

# Linux (cross-compile check)
$env:GOOS='linux';   $env:GOARCH='amd64'; go build -o $env:TEMP\ciliumd_linux ./daemon
```

Run on Windows (must be run with **Administrator** privileges — the agent
enforces an elevated-token / Administrators-group check):

```powershell
.\ciliumd.exe --identity-allocation-mode=crd --enable-k8s=false `
  --bpf-root=$env:TEMP\bpf --state-dir=$env:TEMP\ciliumstate
```

Notes:
- `--devices` and `--run-dir` are **not** valid flags; the set above is a known
  minimal working configuration.
- BPF maps run in an **in-memory backend** on Windows, so the eBPF-for-Windows
  runtime (`ebpfapi.dll`) is not required to start the agent.

## Architecture notes

### Two BPF map abstractions

Cilium has **two** map abstractions, and both are backed in-memory on non-Linux:

1. `pkg/bpf.Map` — backed by `pkg/bpf/map_mem_windows.go` (`memMap`).
2. `pkg/ebpf.Map` — split into a shared `types.go`, a Linux-tagged `map.go`, and
   `map_windows.go` which embeds `bpf.InMemoryMap`. Used by infra maps
   (metricsmap, ratelimitmap, nodemap, etc.).

To extend map behavior on Windows, add the required method to `memMap` in
`pkg/bpf/map_mem_windows.go`.

### Key platform splits added

| Area | Linux | Non-Linux (Windows) |
|------|-------|---------------------|
| `pkg/bpf` maps | `*ebpf.Map` | in-memory `memMap` + pin registry |
| `pkg/ebpf` maps | `map.go` (embeds `*ciliumebpf.Map`) | `map_windows.go` (embeds `bpf.InMemoryMap`) |
| `pkg/common` root check | `utils_linux.go` (`os.Getuid`) | `utils_windows.go` (elevated token / Administrators SID) |
| `daemon/cmd` initEnv | `daemon_main_linux.go` (BPF/mount/clock) | `daemon_main_unspecified.go` (no-op) |
| `pkg/node` address discovery | `address_linux.go` (netlink) | `address_other.go` (standard `net` package) |
| `pkg/datapath` lxcmap | real map via `maps.Cell` | `lxcmap.Cell` (in-memory) wired in `cells_windows.go` |
| `pkg/endpoint` host iface | `host_endpoint_linux.go` (netlink) | `host_endpoint_other.go` (dummy MAC/ifindex) |
| `pkg/envoy` access-log socket | `unixpacket` (SEQPACKET) | `unix` (Windows AF_UNIX has no SEQPACKET) |

### Startup blockers resolved (found by running the agent)

1. Root-privilege check (`os.Getuid() != 0` always fails on Windows).
2. `initEnv` Linux-only BPF/mount/pidfile/clock calls.
3. `ipcache` / generic maps required `ebpfapi.dll` → in-memory `bpf.Map`.
4. Infra maps used `pkg/ebpf.Map` → in-memory `pkg/ebpf` Windows split.
5. IPAM `setDefaultPrefix` panic — non-Linux `FirstGlobalV4Addr` returned an
   empty IP; now enumerates interfaces via the standard `net` package.
6. Endpoint restore nil-map panic — `LxcMap` was a `nil` stub; now the real
   in-memory `lxcmap.Cell` is wired.
7. Host endpoint creation required netlink — split so Windows uses a dummy
   interface and startup completes.
8. Envoy access-log socket used `unixpacket` — fatal on Windows; use `unix`.

### Vendor-free platform constants & wrappers (build fix)

`golang.org/x/sys/unix` is empty on Windows and `vendor/` must **never** be
edited (a `go mod vendor` prunes any hand-added shim files, breaking the
build). Instead, Cilium-owned, build-tagged leaf packages provide the handful
of Linux ABI values and helpers that shared code needs:

| Package | Purpose | Linux impl | Non-Linux impl |
|---------|---------|-----------|----------------|
| `pkg/bpfabi` | BPF map-creation flags (`NoPrealloc`, `NoCommonLRU`, `RdonlyProg`) | alias `unix.BPF_F_*` | literals (`0x1/0x2/0x80`) |
| `pkg/sysabi` | netlink families, route/scope/msg flags (`FamilyV4/V6/All`, `RTTableMain`, `RTNUnreachable`, `ScopeLink`, `RTNHF*`, `MSGTrunc`, `IFFSlave`) | alias `netlink.*` / `unix.*` | literals |
| `pkg/atomicfile` | atomic file replace (API-compatible subset of `renameio`) | delegates to `github.com/google/renameio/v2` | portable temp-file + `os.Rename` |
| `pkg/ebpfperf` | perf ring-buffer reader (`Reader`, `Record`, `NewReader`, `IsUnknownEvent`) | aliases `github.com/cilium/ebpf/perf` | no-op reader that parks until closed |

Errnos and `IPPROTO_*` are taken from the standard `syscall` package (which
defines them on Windows too), so `unix.ENOENT` → `syscall.ENOENT`, etc.
`pkg/bpfabi` is deliberately a leaf (it must not import `pkg/bpf`, which
transitively imports `pkg/datapath/maps`, to avoid an import cycle).

**Rule of thumb:** if a shared/non-linux file references `unix.X`,
`netlink.FAMILY_*`/`SCOPE_*`, `renameio.*`, or `perf.*`, replace it with the
matching `syscall`/`bpfabi`/`sysabi`/`atomicfile`/`ebpfperf` symbol — do not
touch `vendor/`.

## CNC datapath integration (cncshim)

On Windows, Cilium's typed BPF map writes are **mirrored** into the native
eBPF-for-Windows datapath via [`cncshim`](https://github.com/princepereira/cncshim)
(`cncapi.dll`). The in-memory `bpf.Map` remains the source of truth; a
per-map-name **sync hook** forwards each successful `Update`/`Delete` to the
semantic `cncapi` calls.

| Piece | File (build tag) | Role |
|-------|------------------|------|
| Hook registry | `pkg/bpf/cnc_hook_windows.go` (`windows`) | `RegisterMapSyncHook(name, fn)`; invoked from `Map.Update`/`Map.delete`. Cycle-free: map packages register translators, `bpf` never imports them. |
| CNC client | `pkg/cnc/client_windows.go` (`windows`) | Lazily loads `cncapi.dll` via `cncapi.New()`. **Degrades gracefully** — if the DLL / CNC runtime is absent or the process is not elevated, the client stays disabled and every helper is a no-op, so the agent still starts on dev boxes. |
| ipcache translator | `pkg/maps/ipcache/cnc_windows.go` (`windows`) | Registers a hook on `cilium_ipcache_v2` that converts `Key`→`netip.Prefix` and `RemoteEndpointInfo.SecurityIdentity`→`uint32`, calling `SetIdentity`/`DeleteIdentity`. |

The pattern extends to the remaining domains by adding a translator file per map
package: **lxcmap** → `AddOrUpdateEndpoint`/`DeleteEndpoint`, **loadbalancer maps**
→ service/backend calls, **policymap** → `AddOrUpdateEndpointPolicies`/
`DeleteEndpointPolicies`. Add matching helpers to `pkg/cnc`.

`cncapi` is Windows-only (imports `golang.org/x/sys/windows`), so all
integration files are `//go:build windows`; Linux is unaffected. The dependency
is added via `go get` + `go mod vendor` (never by hand-editing `vendor/`).

## Remaining work (next phases)

- Extend the CNC map-sync pattern to the remaining domains:
  - **lxcmap** (endpoint), **loadbalancer maps** (service/backend), **policymap**
    (endpoint policies) — following the ipcache translator pattern above.
  - **hnslib** for network / namespace / policy / endpoint operations.
  - **hcsshim** for container operations where relevant.
- Provide a policy-map factory and program loader so endpoint regeneration
  succeeds (currently retries with "endpoint has nil policyMapFactory").
- Test on a real Windows node with `cncapi.dll` / eBPF-for-Windows present.

## Session history

The full turn-by-turn engineering history is preserved under
[`checkpoints/`](./checkpoints/) (checkpoint 1 is oldest):

| # | Title |
|---|-------|
| 1 | Porting cilium-agent to Windows |
| 2 | Porting cilium-agent to Windows |
| 3 | Porting cilium-agent to Windows |
| 4 | Completing Windows hive DI graph |
| 5 | In-memory BPF maps for Windows runtime |

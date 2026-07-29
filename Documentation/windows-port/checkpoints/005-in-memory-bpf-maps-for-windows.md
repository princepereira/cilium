<overview>
The user wants `cilium-agent` (the `./daemon` binary) to build AND run on Windows nodes while preserving Linux functionality, using build-tag separation (`_linux.go`/`_windows.go`/`_unspecified.go`). Strategy per user guidance: real code stays Linux-tagged; Windows gets best-effort implementations via cncshim (ebpf map updates), hnslib (network components), hcsshim (containers), or dummy/no-op stubs where BPF/netlink isn't feasible. The daemon already COMPILED for both platforms in prior sessions; this session achieved full hive DI graph population, then agent STARTUP (OnStart hooks), and is now implementing an in-memory BPF map backend so the agent can run without the eBPF-for-Windows runtime (ebpfapi.dll).
</overview>

<history>
1. **Rebuilt & validated the Windows hive DI graph** (continuation of prior session's subnet.Cell wiring)
   - `ciliumd.exe hive` now exits 0 — the ENTIRE dependency-injection graph populates on Windows.
   - Verified Linux daemon still builds (exit 0).
   - Committed all accumulated changes (commit `e2b2ef4f2d`) with required trailers.

2. **Tested actual agent startup** (`ciliumd.exe` run, not just `hive`)
   - Discovered `--devices`, `--run-dir` are invalid flags; found valid minimal flags: `--identity-allocation-mode=crd --enable-k8s=false --bpf-root=... --state-dir=...`.
   - **Failure 1**: root-privilege check (`os.Getuid() != 0` always fails on Windows). Fixed by splitting `RequireRootPrivilege` into `utils_linux.go` (real check) and `utils_windows.go` (Administrator/elevated-token check via `golang.org/x/sys/windows`). Added temporary `CILIUM_SKIP_PRIV_CHECK=1` bypass for testing (MUST BE REMOVED before final commit — session is not elevated).
   - **Failure 2**: `initEnv` in daemon_main.go has Linux-specific BPF/mount/pidfile/clock calls. Extracted them into platform helpers: `checkBPFTemplateDir`, `createBPFHeaderFiles`, `mountBPFFilesystems`, `initClockSourceOption` — real in `daemon_main_linux.go`, no-op in `daemon_main_unspecified.go`. Removed `cgroups`/`probes` imports from daemon_main.go.
   - **Failure 3**: `ipcache` OnStart hook creates a BPF map → `load ebpfapi.dll: not found`. This is the core datapath porting challenge.

3. **Investigated cncshim** (fetched https://github.com/princepereira/cncshim)
   - It's a HIGH-LEVEL CNC API (identity, load balancer, endpoint, policy, neighbor) via `cncapi.dll` — it replaces datapath semantics, NOT a generic key/value BPF map. Full cncshim wiring is a large semantic follow-up.
   - Decided: for "runnable" milestone, implement an in-memory BPF map backend at the generic `bpf.Map` layer (the choke point all maps flow through).

4. **Implemented in-memory BPF map backend for `pkg/bpf`** (Windows)
   - Created `pkg/bpf/map_mem_windows.go` with `memMap` type mirroring the `*ebpf.Map` method subset + a pin-path registry for persistence.
   - Changed `Map.m` field type from `*ebpf.Map` to `*memMap` in `map_windows.go`; rerouted 3 creation sites (openOrCreate, open, OpenMap) + Recreate/Unpin/exist to the registry.
   - Fixed `collection.go` (shared) via new `ebpfMap()` accessor (linux returns `m.m`, windows returns nil).
   - Rewrote `ops_windows.go` to use `*memMap` (added `Put`, `NextKeyBytes` to memMap).
   - Rebuilt: pkg/bpf, then full daemon both platforms — all exit 0.
   - Re-ran agent: ipcache map now works in-memory. **Failure 4**: `metricsmap` uses a DIFFERENT abstraction `pkg/ebpf.Map` (embeds `*ciliumebpf.Map`) → still hits ebpfapi.dll.

5. **Started splitting `pkg/ebpf` for Windows** (IN PROGRESS — where compaction occurred)
   - Added exports to `pkg/bpf/map_mem_windows.go`: `InMemoryMap = memMap` alias, `NewInMemoryMap`, `OpenOrCreateInMemoryMap`, `LoadInMemoryMap`, plus `Unpin()`/`IsPinned()` methods and a nil guard in `memUnmarshal`.
   - NOT YET DONE: the actual pkg/ebpf split (types.go shared + map.go tagged linux + new map_windows.go).
</history>

<work_done>
Files created this session:
- `pkg/common/utils_linux.go` — real `RequireRootPrivilege` (os.Getuid check).
- `pkg/common/utils_windows.go` — Windows `RequireRootPrivilege` checking elevated token / Administrators group membership via `golang.org/x/sys/windows` (GetCurrentProcessToken, IsElevated, CreateWellKnownSid(WinBuiltinAdministratorsSid), IsMember). **Contains temporary `CILIUM_SKIP_PRIV_CHECK=1` bypass in `hasAdminPrivilege()` — MUST REMOVE.**
- `daemon/cmd/daemon_main_linux.go` — `checkBPFTemplateDir`, `createBPFHeaderFiles`, `mountBPFFilesystems`, `initClockSourceOption` (real BPF/probes/cgroups impls).
- `daemon/cmd/daemon_main_unspecified.go` — no-op versions of the above (ClockSource=Ktime, EnableBPFClockProbe=false).
- `pkg/bpf/map_mem_windows.go` — in-memory `memMap` backend + `memIterator` + marshalling helpers (memMarshal/memUnmarshal via binary.LittleEndian + encoding.BinaryMarshaler + []byte passthrough) + pin-path registry (pinnedMemMaps) + exports (InMemoryMap, NewInMemoryMap, OpenOrCreateInMemoryMap, LoadInMemoryMap).

Files modified:
- `pkg/common/utils.go` — removed `RequireRootPrivilege` (moved to platform files); removed `os` import (kept fmt).
- `daemon/cmd/daemon_main.go` — replaced inline BPF/mount/clock calls with helper calls; removed `cgroups` and `probes` imports; removed `initClockSourceOption` body (moved to platform files).
- `pkg/bpf/map_windows.go` — field `m *ebpf.Map`→`*memMap`; openOrCreate uses `openOrCreateMemMap`; open uses `loadMemMap`; OpenMap uses `loadMemMap`; Recreate calls `removePinnedMemMap`; Unpin calls `removePinnedMemMap`; exist() checks registry/`m.m`; added `ebpfMap()` returning nil.
- `pkg/bpf/map_linux.go` — added `ebpfMap()` returning `m.m`.
- `pkg/bpf/collection.go` — `m.m`→`m.ebpfMap()` in populateMapReplacements.
- `pkg/bpf/ops_windows.go` — `*ebpf.Map`→`*memMap` in withMap/Delete/Prune/Update/keyIterator.

Work completed:
- [x] Windows hive DI graph fully populates (exit 0)
- [x] Linux daemon still builds
- [x] Committed hive graph work (e2b2ef4f2d)
- [x] Windows privilege check (Administrator)
- [x] initEnv BPF/mount/clock platform split
- [x] In-memory BPF map backend for pkg/bpf (ipcache map now works)
- [ ] Split pkg/ebpf for Windows — IN PROGRESS (exports added to pkg/bpf; pkg/ebpf not yet split)
- [ ] Remove CILIUM_SKIP_PRIV_CHECK test bypass
- [ ] Commit map backend + privilege + initEnv changes (NOT yet committed)
</work_done>

<technical_details>
- **Two separate map abstractions exist**: `pkg/bpf.Map` (uses `m.m *ebpf.Map`, now `*memMap` on Windows) AND `pkg/ebpf.Map` (embeds `*ciliumebpf.Map` anonymously, used by infra maps: metricsmap, ratelimitmap, nodemap, netdev, vtep, encrypt, ipmasq, srv6map, l2responder, etc.). BOTH must be ported to in-memory on Windows.
- **cncshim is NOT a generic map backend** — it's a high-level CNC API (cncapi.dll) for identity/LB/endpoint/policy. Real datapath programming on Windows would wire specific maps to cncshim semantically — a large follow-up, not the current "runnable" milestone.
- **In-memory map design**: `memMap` mirrors the exact `*ebpf.Map` method subset used (Lookup, Update, Delete, NextKey, Iterate, BatchLookup, Put, NextKeyBytes, Type/KeySize/ValueSize/MaxEntries/Flags/FD/Close/Unpin/IsPinned). Because signatures match, higher-level bpf.Map logic (DumpReliablyWithCallback, DeleteAll, ClearAll, resolveErrors) needed NO changes — only field type + creation sites. Keys indexed by marshaled-bytes string; ordered slice for NextKey iteration semantics. Pin-path registry (`pinnedMemMaps`) emulates BPF filesystem pinning so same-path maps share state across open/close.
- **marshalling**: `memMarshal`/`memUnmarshal` handle nil, `[]byte` passthrough, `encoding.BinaryMarshaler/Unmarshaler`, else `binary.Write/Read` with LittleEndian (amd64 native). Cilium map keys/values are fixed-size structs so binary works.
- **memMap.BatchLookup returns (0, ErrKeyNotExist)** = "empty" (dummy); iteration uses Iterate/NextKey instead. Fine at boot since maps start empty.
- **Windows validation loop**: `$env:GOOS='windows'; $env:GOARCH='amd64'; go build -o $env:TEMP\ciliumd.exe ./daemon` then run via Start-Job with `$env:CILIUM_SKIP_PRIV_CHECK='1'` and flags `--identity-allocation-mode=crd --enable-k8s=false --bpf-root=$env:TEMP\bpf --state-dir=$env:TEMP\ciliumstate`, Sleep 30-35s, filter out config-dump lines (`-notmatch 'level=info msg="  --'`), Select-Object -Last N. Each rebuild ~2-3 min.
- **Linux build check**: `$env:GOOS='linux'; go build -o $env:TEMP\ciliumd_linux ./daemon` (needs `-o` since ./daemon collides with daemon/ dir).
- **hive Module description regex** `^[a-zA-Z0-9_\- ]{1,80}$` — no parentheses allowed (bit us on bandwidth module in prior session).
- **PowerShell**: no heredoc; use here-string `@'...'@ | git commit -F -`. `&&` doesn't chain before PowerShell keywords; use `;`. Session is NOT elevated (IsAdmin=False).
- **`pkg/ebpf/map.go` structure**: type aliases (MapSpec, PinType, Hash/Array/LPMTrie/etc constants, PinNone/PinByName, ErrKeyNotExist) + IterateCallback + Map struct (embeds *ciliumebpf.Map, fields: logger, lock, spec, path) + methods (NewMap, LoadRegisterMap, LoadPinnedMap, MapFromID, OpenOrCreate, IterateWithCallback, GetModel, IsEmpty). Uses `unix.BPF_F_RDONLY_PROG` (linux-specific). `map_register.go` is portable (uses m.path, m.logger, m.GetModel()).
- **git commit trailers required**: `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` and `Copilot-Session: 4eff9d43-adcd-4986-9abb-854dbdbd7d0a`.
- **Uncommitted**: everything after commit e2b2ef4f2d (privilege split, initEnv split, both map backends) is uncommitted.
</technical_details>

<important_files>
- `pkg/bpf/map_mem_windows.go`
   - The in-memory BPF map backend — THE core enabler for running without ebpfapi.dll. Contains memMap, memIterator, marshalling, pin registry, and exported InMemoryMap/NewInMemoryMap/OpenOrCreateInMemoryMap/LoadInMemoryMap for pkg/ebpf reuse. Extend here if more ebpf.Map methods are needed (Info, etc.).
- `pkg/bpf/map_windows.go` (`//go:build !linux`)
   - The bpf.Map wrapper now backed by memMap. Field `m *memMap`. Creation sites use registry helpers. `ebpfMap()` returns nil.
- `pkg/ebpf/map.go`
   - The SECOND map abstraction (needs splitting NEXT). Currently shared/untagged, embeds *ciliumebpf.Map. Must become: shared types file + `//go:build linux` map.go + new `//go:build !linux` map_windows.go embedding `*bpf.InMemoryMap`.
- `pkg/ebpf/map_register.go`
   - Portable (no changes needed); calls m.GetModel() which both platform Maps must provide.
- `pkg/common/utils_windows.go`
   - Windows Administrator privilege check. **Remove the CILIUM_SKIP_PRIV_CHECK bypass before final commit.**
- `daemon/cmd/daemon_main_linux.go` / `daemon_main_unspecified.go`
   - Platform split of initEnv's BPF/mount/pidfile/clock operations.
- `daemon/cmd/daemon_main.go`
   - initEnv now calls platform helpers; removed cgroups/probes imports + initClockSourceOption body.
- `pkg/datapath/fake/cells.go` (reference only, do NOT edit)
   - Canonical list of fake datapath providers — consult when a datapath type is missing from hive.
</important_files>

<next_steps>
Immediate (finish pkg/ebpf split):
1. In `pkg/ebpf`, create a shared `types.go` (no build tag) holding the type aliases (MapSpec, PinType), constants (Hash, PerCPUHash, Array, HashOfMaps, LPMTrie, LRUHash, LRUCPUHash, RingBuf, PinNone, PinByName), ErrKeyNotExist, and IterateCallback — MOVE these out of map.go.
2. Tag existing `map.go` with `//go:build linux` (keeps Map struct embedding *ciliumebpf.Map + all methods).
3. Create `pkg/ebpf/map_windows.go` (`//go:build !linux`): Map struct with fields `logger *slog.Logger; lock lock.RWMutex; *bpf.InMemoryMap; spec *MapSpec; path string`. Reimplement NewMap, LoadRegisterMap, LoadPinnedMap (via bpf.LoadInMemoryMap), MapFromID (return error/stub), OpenOrCreate (via bpf.OpenOrCreateInMemoryMap + registerMap + metrics.UpdateMapCapacity), IterateWithCallback, GetModel, IsEmpty. Rely on embedded InMemoryMap for promoted Lookup/Update/Delete/Put/Iterate/Close/Unpin.
4. Build pkg/ebpf for windows; iteratively add any missing methods to memMap (e.g. Info, FD) based on compile errors from consumers.
5. Rebuild full daemon (both GOOS), re-run agent, resolve next OnStart failures (likely more maps, then possibly netlink/proc calls). Keep iterating until agent stays up.

Before committing:
- REMOVE the `CILIUM_SKIP_PRIV_CHECK` bypass from `pkg/common/utils_windows.go`.
- Verify BOTH GOOS=windows AND GOOS=linux build.
- Commit with required trailers.

Later phases (large, not started): real cncshim/hnslib/hcsshim implementations replacing dummy stubs; test on actual Windows node with cncapi.dll/eBPF-for-Windows.

Verification discipline: after every change rebuild BOTH platforms; never break Linux; commit iteratively.
</next_steps>
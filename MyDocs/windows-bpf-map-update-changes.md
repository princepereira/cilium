# Windows BPF map-update changes

Scope: the changes that make the cilium-agent **create, update, share and iterate
eBPF maps against eBPF-for-Windows (efw)** instead of the Linux bpffs/kernel.
Measured with `git diff b0021dc551..HEAD` (the porting commits) on branch
`ppereira-cilium-porting`.

---

## 1. Line count

### `pkg/bpf` — the map create/update/iterate layer
**12 files changed, 327 insertions(+), 11 deletions(-).**

| File | +add | -del | Category |
|------|-----:|-----:|----------|
| `map_legacy_windows.go` *(new)* | 81 | 0 | A. pin sharing (prefer-legacy alias) |
| `map_legacy_other.go` *(new)* | 11 | 0 | A. pin sharing (no-op) |
| `bpffs.go` | 1 | 1 | A. pin path (`MapPath` → `agentMapPath`) |
| `bpffs_windows.go` | 20 | 7 | A. pin path (`/ebpf/global/<name>`) |
| `bpffs_linux.go` | 6 | 0 | A. pin path (unchanged behaviour) |
| `maptype_windows.go` *(new)* | 65 | 0 | B. type/flag translation |
| `maptype_other.go` *(new)* | 20 | 0 | B. type/flag translation (identity) |
| `bpf_ebpf.go` | 11 | 0 | B. call translation in `createMap` |
| `mapbatch_linux.go` *(new)* | 11 | 0 | C. iteration (batch supported) |
| `mapbatch_other.go` *(new)* | 12 | 0 | C. iteration (no batch API) |
| `map_impl.go` | 88 | 2 | A+C. alias hook + non-batch iterator |
| `stats/stats_other.go` | 1 | 1 | minor build-tag fix |

### Reconciler side (so LB frontends are actually pushed to the maps)
**3 files, 40 insertions(+), 1 deletion(-).**

| File | +add | -del |
|------|-----:|-----:|
| `datapath_candidate_windows.go` *(new)* | 21 | 0 |
| `datapath_candidate_other.go` *(new)* | 15 | 0 |
| `bpf_reconciler.go` | 4 | 1 |

**Grand total for the map-update path: 15 files, ~367 insertions, 12 deletions.**
The core BPF map plumbing is ~327 lines; ~7 of the 12 `pkg/bpf` files are new,
build-tag-split (`_windows.go` / `_other.go` / `_linux.go`) so Linux behaviour is
byte-for-byte unchanged.

---

## 2. What the changes do (by category)

### A. Pin path & map sharing — agent updates the *same* object the datapath reads
- **`bpffs.go`**: `MapPath()` now calls `agentMapPath(name)` instead of
  hard-coding `filepath.Join(TCGlobalsPath(), name)`.
- **`bpffs_windows.go`**: `agentMapPath` returns `"/ebpf/global/" + name` using
  **forward slashes** (efw pins live in a driver-owned namespace; `filepath.Join`
  would emit backslashes and produce a distinct, unshared pin). `CheckOrMountFS`
  becomes a no-op (efw has no bpffs mount).
- **`bpffs_linux.go`**: `agentMapPath` = `<bpffs>/tc/globals/<name>` (existing
  Linux behaviour, just factored out).
- **`map_legacy_windows.go`**: `applyLegacyMapAlias()` — when the loaded datapath
  pinned a map under an older name (`cilium_lb4_services` vs the agent's
  `cilium_lb4_services_v2`), the agent **prefers the datapath's existing legacy
  pin** so both sides resolve to one object. Only maps with identical key/value
  geometry are aliased (LB services/backends); ipcache is deliberately excluded.
- **`map_impl.go`**: calls `m.applyLegacyMapAlias()` inside `openOrCreate`.
- **`map_legacy_other.go`**: no-op on non-Windows.

### B. Map type/flag translation — efw rejects Linux map specs
- **`maptype_windows.go`**: `ToPlatformMapType` maps Linux `ebpf.Hash`,
  `ebpf.LPMTrie`, … to the Windows-tagged constants `ebpf.WindowsHash`,
  `ebpf.WindowsLPMTrie`, … `ToPlatformMapFlags` drops Linux `BPF_F_*` flags
  (e.g. `NO_PREALLOC`, `RDONLY_PROG`) that efw rejects with EINVAL.
- **`maptype_other.go`**: identity functions on Linux.
- **`bpf_ebpf.go`**: `createMap` runs the spec (and any inner-map spec) through
  those translators before creation.

### C. Map iteration without the batch API — for reads / CT-NAT GC dumps
- **`mapbatch_linux.go` / `mapbatch_other.go`**: a single const
  `mapBatchAPISupported` (true on Linux, false elsewhere).
- **`map_impl.go`**: `iterateNonBatch` + `lookupRaw` provide a
  `NextKey`/`Lookup` fallback used by `BatchIterator.IterateAll` when the batch
  API is absent (efw has no `BPF_MAP_LOOKUP_BATCH`). Type switches also accept
  the `WindowsHash` / `WindowsLRUHash` / `WindowsLPMTrie` types.

### Reconciler
- **`datapath_candidate_windows.go`**: `platformDatapathCandidate(fe)` returns
  true for `SVCTypeLoadBalancer` so LoadBalancer VIPs are programmed even with
  kube-proxy-replacement off (Windows has no kube-proxy).
- **`bpf_reconciler.go`**: `isDatapathCandidate` now consults
  `platformDatapathCandidate`.

---

## 3. External APIs / ebpf-go

**We do NOT call any custom or external Windows syscall API, and we did not fork
anything.** All map operations go through **upstream ebpf-go**:

- Dependency: `github.com/cilium/ebpf v0.22.0` in `go.mod` — the upstream release
  that added **native Windows / eBPF-for-Windows support**. There is **no
  `replace` directive** pointing at a fork.
- Every map create/update/lookup/pin/iterate uses ebpf-go
  (`ebpf.LoadPinnedMap`, `m.Lookup`, `m.NextKey`, `MapSpec`, `MapType`, …). On
  Windows, ebpf-go internally routes these to the efw runtime.
- The Windows-tagged constants we reference (`ebpf.WindowsHash`,
  `ebpf.WindowsLPMTrie`, `ebpf.WindowsLRUHash`, …) are **provided by ebpf-go's
  platform-tagged enum** — we do not define them.
- No **cgo**, no direct `libbpf`, and no hand-written efw API bindings in this
  layer. `github.com/cilium/ebpf/cmd/bpf2go` in `go.mod` is only a build-time
  code-gen tool, not a runtime dependency.

The datapath objects themselves (the `.sys`/eBPF programs and their initial
pins) are produced by the separate **eBPF-for-Windows / winebpfmap** components;
this PR only changes how the Go agent *talks to* those maps.

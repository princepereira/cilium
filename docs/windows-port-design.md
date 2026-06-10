# Windows Cilium Agent — Design Document

## Overview

This document describes the architectural changes made to port the Cilium agent to Windows, based on [PR #2](https://github.com/princepereira/cilium/pull/2). The port introduces a minimal Windows agent focused on **Service Load Balancing** via the CNC (Container Networking Compute) DLL, while excluding Linux-specific subsystems that have no Windows equivalent.

**Total scope:** 238 files changed (+8711, -621 lines)

---

## 1. High-Level Architecture

### Linux Agent (Original)
```
┌─────────────────────────────────────────────────┐
│                  cilium-agent                     │
├──────────────┬──────────────┬───────────────────┤
│ Infrastructure│ ControlPlane │     Datapath       │
│  (API, CNI,  │ (Identity,   │  (eBPF loader,    │
│   metrics,   │  Policy,     │   iptables,       │
│   KVStore,   │  Endpoints,  │   tunnel, route,  │
│   health)    │  IPAM, LB,   │   neighbor, XDP)  │
│              │  Hubble, BGP)│                    │
└──────────────┴──────────────┴───────────────────┘
                      │
               eBPF Maps (kernel)
```

### Windows Agent (New)
```
┌─────────────────────────────────────────────────┐
│              cilium-agent (Windows)               │
├─────────────────────────────────────────────────┤
│  K8s Client → StateDB Tables → CNC Reconciler   │
│                                                   │
│  Reflectors    Writer    CNCOps    CNCLBMaps     │
│  (K8s svc/ep) (tables)  (reconcile) (DLL calls) │
└─────────────────────────────────────────────────┤
                      │
              CNC DLL (cnc.sys / Windows kernel)
```

---

## 2. Build Constraint Strategy

### Approach: `//go:build !windows` on Linux-only files + `_windows.go` alternatives

Since the existing Cilium codebase is deeply tied to Linux kernel features (eBPF, netlink, cgroups, iptables, xfrm), the port uses Go build tags to **exclude** these files from Windows compilation and provides **stub or alternative implementations** where needed.

### Categories of changes:

| Category | Count | Description |
|----------|-------|-------------|
| `//go:build !windows` added | ~95 files | Existing Linux files tagged to exclude from Windows build |
| `*_windows.go` / `stub_windows.go` added | ~75 files | New Windows implementations or no-op stubs |
| New Windows-specific code | ~10 files | Core new functionality (CNC client, LB maps, reconciler) |
| Vendor additions | 7 files | `cncshim` DLL bindings |
| Documentation | 4 files | Architecture docs, build guide, session notes |

---

## 3. Files Made Linux-Only (`//go:build !windows`)

### 3.1 Agent Core (`daemon/cmd/`)

| File | Reason | Windows Alternative |
|------|--------|---------------------|
| `cells.go` | Imports 50+ Linux-specific cells (eBPF, iptables, envoy, hubble, etc.) | `windows_stubs.go` — minimal agent with only LB cells |
| `daemon.go` | References ipsec, probes, endpoint regeneration, WireGuard | `windows_stubs.go` — empty stubs |
| `daemon_main.go` | Uses eBPF rlimit, cgroups, BPF probes, viper config | `windows_stubs.go` — simplified `NewAgentCmd()` |
| `root.go` | Full cobra command with all hive flags registered | `windows_stubs.go` — bare cobra command |
| `cni/config.go` | Writes CNI config to `/etc/cni/net.d/` (Linux networking) | `cni/config_windows.go` — no-op (HNS handles CNI on Windows) |
| `endpoint_restore.go` | BPF endpoint restoration | Stub in `windows_stubs.go` |
| `hostips-sync.go` | Syncs to lxc BPF map | Stub in `windows_stubs.go` |
| `metrics.go` | BPF metrics map registration | Stub in `windows_stubs.go` |

### 3.2 BPF Package (`pkg/bpf/`)

| File | Reason | Windows Alternative |
|------|--------|---------------------|
| `bpf.go` | Linux eBPF syscalls | `bpf_windows.go` — no-op stubs for `MapRegister`, `ReadBPFHeader`, etc. |
| `collection.go` | cilium/ebpf collection loading | `collection_windows.go` — empty collection ops |
| `pinning.go` | BPF map pinning in bpffs | No equivalent needed |
| `unused_tailcalls.go` | Tail call cleanup | No equivalent needed |

`bpf_windows.go` provides type stubs (`Map`, `MapIterator`, etc.) so packages that reference BPF types still compile on Windows.

### 3.3 Datapath Linux (`pkg/datapath/linux/`)

| Subsystem | Files Tagged | Windows Stub |
|-----------|-------------|--------------|
| `device/` | 6 files (cell, manager, reconciler, table, vlan) | `stub_windows.go` — empty device manager |
| `ipsec/` | 3 files (cell, xfrm_collector, xfrm_state_cache) | `stub_windows.go` — no-op IPsec |
| `config/` | 1 file | `stub_windows.go` — empty header writer |
| `probes/` | 5 files | Extended `probes_unspecified.go` for Windows |
| `route/reconciler/` | 6 files | `stub_windows.go` — no-op route reconciler |
| `routing/` | 2 files | `stub_windows.go` — no-op routing |
| `utime/` | 2 files | `stub_windows.go` — no-op utime |
| `netdevice/` | 1 file | `netdevice_windows.go` — no-op |
| `bandwidth/ops.go` | 1 file | Not needed on Windows |

### 3.4 Maps (`pkg/maps/`)

| Map Package | Files Tagged | Windows Alternative |
|-------------|-------------|---------------------|
| `policymap/` | 2 files | `policymap_windows.go` — in-memory stub |
| `ipcache/` | 1 file (refactored) | `ipcache_windows.go` — in-memory stub |
| `ctmap/` | 6 files | `ctmap_windows.go` — no-op |
| `nat/` | 5 files | `nat_windows.go` — no-op |
| `signalmap/` | 2 files | `stub_windows.go` — no-op |
| `egressmap/` | 2 files | `policy_windows.go` — in-memory |
| `srv6map/` | 4 files | `windows.go` — in-memory |
| `lxcmap/` | 1 file | `stub_windows.go` — in-memory |
| `cidrmap/` | 1 file | `cidrmap_windows.go` — in-memory |
| Others | ~15 files | Various stubs |

### 3.5 Other Packages

| Package | Files Tagged | Windows Alternative |
|---------|-------------|---------------------|
| `pkg/act/` | 1 file | `stub_windows.go` |
| `pkg/datapath/agentliveness/` | 1 file | `stub_windows.go` |
| `pkg/datapath/alignchecker/` | 1 file | `stub_windows.go` |
| `pkg/datapath/connector/` | 4 files | `stub_windows.go` — no veth/netkit |
| `pkg/datapath/iptables/` | 3 files | `stub_windows.go` |
| `pkg/datapath/prefilter/` | 3 files | Not needed |
| `pkg/datapath/vtep/` | 1 file | `stub_windows.go` |
| `pkg/datapath/xdp/` | 1 file | `xdp_windows.go` — no-op |
| `pkg/ebpf/` | 2 files | `map_windows.go` |
| `pkg/identity/cache/` | 4 files | `stub_windows.go` — no-op allocator |
| `pkg/k8s/hostfirewallbypass/` | 2 files | `stub_windows.go` |
| `pkg/loadbalancer/maps/` | 4 files | `cell_windows.go` + `lbmaps_windows.go` |
| `pkg/loadbalancer/reconciler/` | 3 files | `reconciler_windows.go` |
| `pkg/loadbalancer/reflectors/` | 2 files | `stub_windows.go` |
| `pkg/monitor/agent/` | 5 files | `stub_windows.go` |
| `pkg/signal/` | 2 files | `stub_windows.go` |
| `pkg/socketlb/` | 2 files | `stub_windows.go` |
| `pkg/node/manager/` | 1 file (refactored) | `checkpointfile_windows.go` |
| `pkg/proxy/proxyports/` | 1 file (refactored) | `pendingfile_windows.go` |
| `pkg/mtu/` | 1 file | `endpoint_updater_windows.go` |

---

## 4. New Windows Implementation

### 4.1 CNC Client (`pkg/datapath/win/client.go`)

**Purpose:** Manages the lifecycle of the CNC DLL connection.

```go
type CNCClient struct {
    mu       sync.Mutex
    api      cncapi.CNCApi
    logger   *slog.Logger
    ready    chan struct{}
    cancelFn context.CancelFunc
}
```

- Initializes CNC DLL (`CncInitialize`) on start
- Retries with backoff if initialization fails (e.g., DLL locked by another process)
- Provides `Ready()` channel for downstream consumers
- Calls `CncUninitialize` on shutdown

### 4.2 CNC LB Maps (`pkg/loadbalancer/maps/lbmaps_windows.go`)

**Purpose:** Implements the `LBMaps` interface using CNC DLL calls instead of eBPF maps.

```go
type CNCLBMaps struct {
    api             cncapi.CNCApi
    services        map[string]serviceEntry      // in-memory tracking
    backends        map[uint32]backendEntry       // in-memory tracking
    pendingSlots    map[string][]uint32           // accumulates backends per service
    cncBackends     map[uint16][]cncapi.BackendInfo  // tracks CNC-side state
    createdServices map[uint16]bool              // avoids duplicate creates
}
```

Key operations:
- `UpdateService()` → `CncCreateLoadBalancerService()` + `CncUpdateLoadBalancerServiceBackends()`
- `UpdateBackend()` → `CncCreateLoadBalancerBackends()`
- `DeleteService()` → `CncDeleteLoadBalancerService()`
- `DeleteBackend()` → `CncDeleteLoadBalancerBackends()`

**Critical detail:** The reconciler writes service values in network byte order, but CNC expects host byte order for serviceID. A conversion via `byteorder.NetworkToHost16()` is applied.

### 4.3 CNC Reconciler (`pkg/loadbalancer/reconciler/reconciler_windows.go`)

**Purpose:** Implements `reconciler.Operations[*loadbalancer.Frontend]` for the StateDB reconciler pattern.

```go
type CNCOps struct {
    LBMaps            maps.LBMaps
    backends          statedb.Table[*loadbalancer.Backend]
    serviceIDAlloc    idAllocator[loadbalancer.ServiceID]
    backendIDAlloc    idAllocator[loadbalancer.BackendID]
    backendReferences map[loadbalancer.L3n4Addr]int
}
```

Operations:
- `Update(*Frontend)` — creates service + backends in CNC
- `Delete(*Frontend)` — removes service from CNC
- `Prune()` — no-op (CNC state owned by this agent)

### 4.4 Windows Agent Cell Graph (`daemon/cmd/windows_stubs.go`)

```go
Agent = cell.Module("agent", "Cilium Agent Windows",
    winDatapath.Cell,           // CNC client lifecycle
    client.Cell,                // K8s API client
    node.LocalNodeStoreCell,    // Local node info
    loadbalancer.ConfigCell,    // LB configuration
    writer.Cell,                // StateDB table writer
    reflectors.Cell,            // K8s → StateDB reflectors
    maps.Cell,                  // CNCLBMaps (DLL backend)
    reconciler.Cell,            // CNCOps (reconciliation)
)
```

### 4.5 Vendor: cncshim (`vendor/github.com/princepereira/cncshim/`)

Provides Go bindings to the Windows CNC DLL via `syscall.LazyDLL`:

| File | Purpose |
|------|---------|
| `client.go` | DLL function wrappers (Initialize, CreateService, UpdateBackends, etc.) |
| `abi_types.go` | C-compatible struct definitions for DLL interop |
| `abi_convert.go` | Go ↔ ABI type conversions |
| `cnciface.go` | `CNCApi` interface definition |
| `types.go` | High-level Go types (BackendInfo, LoadBalancerInfo) |
| `mock.go` | Mock implementation for testing |
| `errors.go` | HRESULT error wrapping |

---

## 5. Data Flow: Service Load Balancing

### 5.1 Linux Data Flow (eBPF-based)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  K8s API     │────►│  Reflectors  │────►│  StateDB     │
│  (Services,  │     │  (K8s watch  │     │  (Frontend,  │
│   Endpoints, │     │   + file     │     │   Backend    │
│   EndpSlice) │     │   reflector) │     │   tables)    │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                  │ reconcile loop
                                           ┌──────▼───────┐
                                           │   BPFOps     │
                                           │  (ID alloc,  │
                                           │   Maglev,    │
                                           │   NodePort,  │
                                           │   wildcard,  │
                                           │   orphan GC) │
                                           └──────┬───────┘
                                                  │
                                           ┌──────▼───────┐
                                           │   LBMaps     │
                                           │  (BPF map    │
                                           │   wrappers)  │
                                           └──────┬───────┘
                                                  │ bpf syscalls
                              ┌────────────────────┼────────────────────┐
                              │                    │                    │
                       ┌──────▼───────┐     ┌─────▼──────┐     ┌──────▼───────┐
                       │ Service Map  │     │ Backend Map│     │  RevNat Map  │
                       │ (slot-based: │     │ (ID→addr:  │     │ (svcID→VIP:  │
                       │  slot0=master│     │   port)    │     │   port)      │
                       │  slot1-N=BE) │     │            │     │              │
                       └──────┬───────┘     └─────┬──────┘     └──────┬───────┘
                              │                    │                    │
                              └────────────────────┼────────────────────┘
                                                   │
                                            ┌──────▼───────┐
                                            │ Linux Kernel │
                                            │  (eBPF prog  │
                                            │   tc/XDP     │
                                            │   hook does  │
                                            │   DNAT/LB)   │
                                            └──────────────┘
```

**Linux-specific details:**
- **Slot-based service map**: Slot 0 stores service metadata (type, flags, backend count). Slots 1–N store individual backend references. This allows atomic per-backend updates.
- **RevNat map**: Separate map that maps `serviceID → frontend VIP:port`. Used by eBPF to reverse-NAT return traffic.
- **Maglev**: Consistent hashing table written alongside service entries for stable backend selection.
- **NodePort expansion**: Each NodePort service creates entries for every node IP + wildcard (0.0.0.0).
- **Source ranges**: Separate map entries for LoadBalancer IP access control.
- **Orphan GC**: BPFOps tracks backend references across all frontends and deletes backends no longer referenced by any service.
- **ID restoration**: On restart, BPFOps reads existing BPF maps to restore previously-allocated service/backend IDs, avoiding traffic disruption.

### 5.2 Windows Data Flow (CNC DLL-based)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  K8s API     │────►│  Reflectors  │────►│  StateDB     │
│  (Services,  │     │  (K8s watch) │     │  (Frontend,  │
│   Endpoints) │     │              │     │   Backend    │
└──────────────┘     └──────────────┘     │   tables)    │
                                           └──────┬───────┘
                                                  │ reconcile
                                           ┌──────▼───────┐
                                           │   CNCOps     │
                                           │  (ID alloc,  │
                                           │   translate) │
                                           └──────┬───────┘
                                                  │
                                           ┌──────▼───────┐
                                           │  CNCLBMaps   │
                                           │  (byte-order │
                                           │   convert,   │
                                           │   in-memory  │
                                           │   tracking)  │
                                           └──────┬───────┘
                                                  │ DLL calls
                                           ┌──────▼───────┐
                                           │   CNC DLL    │
                                           │  (cnc.sys    │
                                           │   kernel     │
                                           │   driver)    │
                                           └──────────────┘
```

**Windows-specific details:**
- **No slot concept**: CNC uses `CreateService` + `UpdateServiceBackends(newList, oldList)` — an atomic full-replace of the backend set.
- **RevNat internal**: CNC manages reverse-NAT internally; no separate map needed from the agent.
- **No Maglev**: Backend selection algorithm is handled inside the CNC kernel driver.
- **No NodePort/wildcard**: Only ClusterIP services supported currently.
- **No orphan GC**: Agent owns all CNC LB state; `Prune()` is a no-op.
- **Fresh IDs on restart**: No ID restoration — IDs are re-allocated each time the agent starts.
- **In-memory mirrors**: `CNCLBMaps` keeps local copies since CNC has no "dump all entries" API.

### 5.3 Side-by-Side Comparison

```
          LINUX                                    WINDOWS
          ─────                                    ───────

  K8s API Server                            K8s API Server
       │                                         │
       ▼                                         ▼
  Reflectors (K8s + File)                   Reflectors (K8s only)
       │                                         │
       ▼                                         ▼
  StateDB Tables                            StateDB Tables
  (Frontend, Backend)                       (Frontend, Backend)
       │                                         │
       ▼                                         ▼
  BPFOps                                    CNCOps
  ├─ ID alloc (restored from maps)          ├─ ID alloc (fresh)
  ├─ Maglev hash tables                     ├─ No Maglev
  ├─ NodePort expansion                     ├─ ClusterIP only
  ├─ Wildcard entries                       ├─ No wildcards
  ├─ Source range maps                      ├─ No source ranges
  ├─ Backend orphan tracking                ├─ Simple backend count
  └─ Slot-based updates                     └─ Atomic full-replace
       │                                         │
       ▼                                         ▼
  LBMaps (BPF map syscalls)                 CNCLBMaps (DLL interop)
  ├─ Service4Map / Service6Map              ├─ CreateService
  ├─ Backend4Map / Backend6Map              ├─ CreateBackends
  ├─ RevNat4Map / RevNat6Map                ├─ UpdateServiceBackends
  ├─ Affinity map                           └─ DeleteService/Backends
  ├─ Source range map                            │
  └─ Maglev outer/inner maps                    │
       │                                         │
       ▼                                         ▼
  Linux Kernel (eBPF tc/XDP)                CNC Kernel Driver (cnc.sys)
  └─ DNAT at packet level                   └─ DNAT at VFP/packet level
```

### 5.4 Detailed Code Flow (Windows) — Function-Level Trace

```
═══════════════════════════════════════════════════════════════════════════════════
                    WINDOWS CILIUM AGENT — LB RECONCILIATION FLOW
═══════════════════════════════════════════════════════════════════════════════════

CELLS INVOLVED:
  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
  │ client.Cell    │  │ reflectors.Cell│  │  writer.Cell   │  │ reconciler.Cell│
  │ (K8s client)   │  │ (K8s watcher)  │  │ (StateDB write)│  │ (CNCOps)       │
  └────────────────┘  └────────────────┘  └────────────────┘  └────────────────┘
  ┌────────────────┐  ┌────────────────┐
  │  maps.Cell     │  │ winDatapath.Cell│
  │ (CNCLBMaps)    │  │ (CNC DLL conn) │
  └────────────────┘  └────────────────┘

═══════════════════════════════════════════════════════════════════════════════════

STEP 1: K8s EndpointSlice Watch
───────────────────────────────
  File: pkg/loadbalancer/reflectors/k8s.go
  Func: endpointsEvents() (~line 898)

  K8s API ──ListerWatcher──► endpointsEvents()
                                    │
                                    ▼
                             upsertEndpointEvent{eps}


STEP 2: Reflector processes event → calls Writer
────────────────────────────────────────────────
  File: pkg/loadbalancer/reflectors/k8s.go
  Func: runServiceEndpointsReflector() (~line 324)

  upsertEndpointEvent ──► runServiceEndpointsReflector()
                                    │
                                    ▼
                          p.Writer.UpsertBackends(txn, name, source.Kubernetes, backends)
                          p.Writer.UpsertServiceAndFrontends(txn, ...)


STEP 3: Writer inserts into StateDB tables
──────────────────────────────────────────
  File: pkg/loadbalancer/writer/writer.go
  Funcs: UpsertBackends() (~line 641), UpsertServiceAndFrontends() (~line 330)

  Writer.UpsertBackends()
      │
      ├──► w.bes.Insert(txn, &backend)        // backends table
      │
      └──► w.fes.Insert(txn, frontend)        // frontends table
                                               // (marks Status = Pending)
           txn.Commit()                        // ATOMIC — visible to readers


STEP 4: Reconciler watches frontends table
──────────────────────────────────────────
  File: pkg/loadbalancer/reconciler/reconciler_windows.go
  Func: newCNCReconciler() (~line 92)

  reconciler.Register(
      fes,                    // RWTable[*Frontend]
      ...,
      ops,                    // CNCOps (implements Operations[*Frontend])
  )
      │
      │  (internally: watches Changes() on frontends table)
      │
      ▼
  When a Frontend has Status=Pending → calls ops.Update(fe)
  When a Frontend is deleted        → calls ops.Delete(fe)


STEP 5: CNCOps.Update() — reconcile one frontend
─────────────────────────────────────────────────
  File: pkg/loadbalancer/reconciler/reconciler_windows.go
  Func: CNCOps.Update() (~line 159)

  CNCOps.Update(fe *Frontend)
      │
      ├─ serviceID := ops.serviceIDAlloc.Alloc(fe.Address)
      │
      ├─ for each backend in sortedBackends(fe):
      │      beID := ops.backendIDAlloc.Alloc(be.Address)
      │      │
      │      ├──► ops.upsertBackend(beID, be)                    [STEP 6a]
      │      │
      │      └──► ops.LBMaps.UpdateService(slotKey, slotVal)     [STEP 6b]
      │           (slot > 0: backend slot)
      │
      └─ ops.LBMaps.UpdateService(masterKey, masterVal)          [STEP 6c]
         (slot = 0: master entry with backend count)


STEP 6: CNCOps calls LBMaps interface
──────────────────────────────────────
  File: pkg/loadbalancer/reconciler/reconciler_windows.go
  Func: upsertBackend() (~line 346)

  6a) ops.LBMaps.UpdateBackend(backendKey, backendValue.ToNetwork())
  6b) ops.LBMaps.UpdateService(slotKey.ToNetwork(), slotVal.ToNetwork())
  6c) ops.LBMaps.UpdateService(masterKey.ToNetwork(), masterVal.ToNetwork())


STEP 7: CNCLBMaps translates to CNC DLL calls
──────────────────────────────────────────────
  File: pkg/loadbalancer/maps/lbmaps_windows.go
  Funcs: UpdateBackend() (~line 331), UpdateService() (~line 104)

  7a) UpdateBackend(key, value):
      │
      └──► api.CreateLoadBalancerBackends([]BackendInfo{...})
           (delete-recreate on ERROR_ALREADY_EXISTS)

  7b) UpdateService(key, value) [slot > 0]:
      │
      └──► pendingSlots[frontend] = append(..., backendID)
           (accumulate — no DLL call yet)

  7c) UpdateService(key, value) [slot = 0 / master]:
      │
      ├──► serviceID = byteorder.NetworkToHost16(value.GetRevNat())
      │
      ├──► api.CreateLoadBalancerService(serviceID, lbInfo)
      │    (skip if already created)
      │
      └──► api.UpdateLoadBalancerServiceBackends(
               serviceID, lbInfo,
               newBackends,      // from pendingSlots
               oldBackends,      // from cncBackends[serviceID]
           )
           │
           └──► CNC DLL (cnc.sys kernel driver) performs DNAT programming

═══════════════════════════════════════════════════════════════════════════════════

COMPLETE CALL CHAIN (single path):
───────────────────────────────────

  K8s API
    → endpointsEvents()                         [reflectors/k8s.go:898]
    → runServiceEndpointsReflector()            [reflectors/k8s.go:324]
    → Writer.UpsertBackends()                   [writer/writer.go:641]
    → w.fes.Insert(txn, fe); txn.Commit()       [writer/writer.go:330]
    → reconciler detects Pending frontend       [reconciler framework]
    → CNCOps.Update(fe)                         [reconciler/reconciler_windows.go:159]
    → ops.upsertBackend() + ops.LBMaps.UpdateService()
    → CNCLBMaps.UpdateBackend()                 [maps/lbmaps_windows.go:331]
    → CNCLBMaps.UpdateService()                 [maps/lbmaps_windows.go:104]
    → api.CreateLoadBalancerService()           [cncshim/cncapi/client.go:390]
    → api.UpdateLoadBalancerServiceBackends()   [cncshim/cncapi/client.go:400]
    → CNC DLL syscall → kernel VFP rules

═══════════════════════════════════════════════════════════════════════════════════
```

#### Cell Dependency Graph

```
═══════════════════════════════════════════════════════════════════════════════════
                     WINDOWS AGENT — CELL INTERCONNECTION MAP
═══════════════════════════════════════════════════════════════════════════════════

Each arrow shows what TYPE flows from one cell to another via Hive DI.
Arrows labeled with the Go type that is Provided by the source and consumed
by the destination.

                        ┌─────────────────────┐
                        │   Hive Framework     │
                        │                      │
                        │  provides to ALL:    │
                        │  • *slog.Logger      │
                        │  • cell.Lifecycle     │
                        │  • *statedb.DB       │
                        │  • job.Group         │
                        │  • cell.Health       │
                        └──────────┬───────────┘
                                   │
          ┌────────────────────────┼─────────────────────────┐
          │                        │                          │
          ▼                        ▼                          ▼
┌──────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
│ winDatapath.Cell │  │    client.Cell         │  │   Config Cells        │
│ (datapath-win)   │  │    (K8s client)        │  │                       │
│                  │  │                        │  │  loadbalancer.Config  │
│ Provide:         │  │ Provide:               │  │  Cell                 │
│  newCNCClient()  │  │  NewClientset()        │  │  maglev.Cell          │
│                  │  │                        │  │  kpr.Cell             │
│ OUTPUT:          │  │ OUTPUT:                │  │  nodeipamconfig.Cell  │
│  *CNCClient     │  │  client.Clientset      │  │  lbipamconfig.Cell    │
│                  │  │                        │  │  k8s.DefaultConfig    │
└────────┬─────────┘  └────────┬──────────────┘  │                       │
         │                     │                  │ OUTPUT:               │
         │                     │                  │  loadbalancer.Config  │
         │                     │                  │  loadbalancer.ExtCfg  │
         │                     │                  │  maglev.Config        │
         │                     │                  │  k8s.Config           │
         │                     │                  └───────┬───────────────┘
         │                     │                          │
         │                     │    ┌─────────────────────┘
         │                     │    │
         │                     ▼    ▼
         │            ┌────────────────────────────────────────────────┐
         │            │               writer.Cell                      │
         │            │         (loadbalancer-writer)                   │
         │            │                                                │
         │            │ Creates (private):                             │
         │            │   RWTable[*Service]                            │
         │            │   RWTable[*Frontend]                           │
         │            │   RWTable[*Backend]                            │
         │            │                                                │
         │            │ Provide (public):                              │
         │            │   *Writer            ◄── writerParams:         │
         │            │   Table[*Service]        • *statedb.DB         │
         │            │   Table[*Frontend]       • loadbalancer.Config │
         │            │   Table[*Backend]        • Table[NodeAddress]  │
         │            │                          • Table[*LocalNode]   │
         │            │                          • source.Sources      │
         │            └───────────┬──────────────┬───────────────────┘
         │                        │              │
         │         ┌──────────────┘              │
         │         │                             │
         │         ▼                             │
         │  ┌───────────────────────────────┐   │
         │  │      reflectors.Cell          │   │
         │  │   (loadbalancer-reflectors)    │   │
         │  │                               │   │
         │  │  K8sReflectorCell:            │   │
         │  │   provideK8sReflector()       │   │
         │  │                               │   │
         │  │  reflectorParams:             │   │
         │  │   • client.Clientset ◄────────│───│──── client.Cell
         │  │   • *Writer          ◄────────│───│──── writer.Cell
         │  │   • Table[LocalPod]  ◄────────│───│──── k8stables
         │  │   • loadbalancer.Config       │   │
         │  │   • loadbalancer.ExtConfig    │   │
         │  │   • Table[*LocalNode]         │   │
         │  │   • HaveNetNSCookieSupport    │   │
         │  │                               │   │
         │  │  FileReflectorCell: no-op     │   │
         │  │  NetnsCookieSupport: false    │   │
         │  └───────────────────────────────┘   │
         │                                      │
         │                                      │
         ▼                                      ▼
┌──────────────────────┐            ┌────────────────────────────────────┐
│    maps.Cell         │            │        reconciler.Cell             │
│  (loadbalancer-maps) │            │   (loadbalancer-reconciler)        │
│                      │            │                                    │
│ Provide:             │            │ Provide:                           │
│  newCNCLBMaps()      │            │  newCNCOps()                       │
│                      │            │  newCNCReconciler()                 │
│ lbmapsParams:        │            │                                    │
│  • *slog.Logger      │            │ cncOpsParams:                      │
│  • maglev.Config     │            │  • LBMaps        ◄──── maps.Cell  │
│  • loadbalancer.Cfg  │            │  • Table[*Backend]◄──── writer.Cell│
│  • loadbalancer.Ext  │            │  • *slog.Logger                    │
│                      │            │                                    │
│ OUTPUT:              │            │ newCNCReconciler params:            │
│  LBMaps (interface)──│──────────► │  • *CNCOps                         │
│                      │            │  • Table[*Frontend] ◄── writer.Cell│
│                      │            │  • *Writer          ◄── writer.Cell│
│                      │            │  • reconciler.Params (framework)   │
│                      │            │                                    │
│ SetAPI() injected    │            │ OUTPUT:                             │
│ at runtime by:       │            │  Promise[Reconciler[*Frontend]]    │
│ wireCNCClientToLBMaps│            └────────────────────────────────────┘
└──────────┬───────────┘
           │
           │
           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    cell.Invoke(wireCNCClientToLBMaps)                    │
│                                                                         │
│  Consumes:                                                              │
│    • *CNCClient  ◄──── winDatapath.Cell                                │
│    • LBMaps      ◄──── maps.Cell                                       │
│    • cell.Lifecycle (from Hive)                                         │
│                                                                         │
│  OnStart hook:                                                          │
│    go func() {                                                          │
│        <-client.Ready()               // wait for CNC DLL              │
│        lbMaps.(apiSetter).SetAPI(     // inject CNC API into maps      │
│            client.API(),                                                │
│        )                                                                │
│    }()                                                                  │
│                                                                         │
│  This bridges winDatapath.Cell ──► maps.Cell at runtime                │
└─────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════════
  SUMMARY: What each cell PROVIDES and CONSUMES
═══════════════════════════════════════════════════════════════════════════════════

  CELL                  │ PROVIDES (OUTPUT)            │ CONSUMES (INPUT)
  ──────────────────────┼──────────────────────────────┼──────────────────────────
  winDatapath.Cell      │ *CNCClient                   │ Logger, Lifecycle
  client.Cell           │ client.Clientset             │ Logger, Lifecycle
  loadbalancer.ConfigCell│ Config, ExternalConfig      │ *DaemonConfig
  maglev.Cell           │ maglev.Config                │ —
  node.LocalNodeStore   │ Table[*LocalNode]            │ ClusterInfo
  writer.Cell           │ *Writer, Table[*Frontend],   │ *statedb.DB, Config,
                        │ Table[*Backend],             │ Table[NodeAddress],
                        │ Table[*Service]              │ Table[*LocalNode],
                        │                              │ source.Sources
  reflectors.Cell       │ K8sReflectorRegistered       │ Clientset, *Writer,
                        │                              │ Table[LocalPod],
                        │                              │ Config, Table[*LocalNode]
  maps.Cell             │ LBMaps (interface)           │ Logger, Config,
                        │                              │ maglev.Config
  reconciler.Cell       │ *CNCOps,                     │ LBMaps, Table[*Backend],
                        │ Promise[Reconciler]          │ Table[*Frontend], *Writer
  wireCNCClientToLBMaps │ (side-effect only)           │ *CNCClient, LBMaps

═══════════════════════════════════════════════════════════════════════════════════

  SHARED StateDB TABLES (the communication bus between cells):

  ┌─────────────────────┐
  │ Table: "frontends"  │ Written by: writer.Cell (via reflectors.Cell calls)
  │                     │ Read by:    reconciler.Cell (watches Changes)
  ├─────────────────────┤
  │ Table: "backends"   │ Written by: writer.Cell
  │                     │ Read by:    reconciler.Cell (via fe.Backends iterator)
  ├─────────────────────┤
  │ Table: "services"   │ Written by: writer.Cell
  │                     │ Read by:    (metadata only, not directly by reconciler)
  └─────────────────────┘

═══════════════════════════════════════════════════════════════════════════════════
```

---

## 6. Features Omitted on Windows

The following features present in the Linux agent are **not implemented** in the Windows port:

### 6.1 Not Applicable (Different OS mechanism handles it)

| Feature | Linux Implementation | Windows Equivalent |
|---------|---------------------|-------------------|
| CNI config writing | `daemon/cmd/cni/config.go` writes to `/etc/cni/net.d/` | HNS (Host Networking Service) manages container networking |
| eBPF datapath | `pkg/datapath/linux/` — BPF programs loaded into kernel | CNC DLL provides kernel datapath |
| iptables/nftables | `pkg/datapath/iptables/` | Windows Filtering Platform (WFP) via CNC |
| veth/netkit interfaces | `pkg/datapath/connector/` | HNS virtual adapters |
| Route management | `pkg/datapath/linux/route/` | Windows route table managed by HNS/CNC |
| Neighbor discovery | `pkg/datapath/neighbor/` | Windows ARP handled by HNS |

### 6.2 Not Yet Implemented (Could be added later)

| Feature | Linux Implementation | Status on Windows |
|---------|---------------------|-------------------|
| **Network Policy** | `pkg/policy/`, identity allocation, policymap | Stubbed — no enforcement |
| **Identity Management** | `pkg/identity/cache/` — allocates security identities | Stubbed — no-op allocator |
| **IPCache** | `pkg/maps/ipcache/` — IP→Identity mapping | In-memory stub, not enforced |
| **Endpoints** | `pkg/endpoint/` — per-pod BPF programs | Not applicable (CNC handles per-pod) |
| **Hubble** | Observability via BPF events | Not implemented |
| **ClusterMesh** | Multi-cluster service discovery | Not included |
| **BGP** | BGP peering for service advertisement | Not included |
| **Egress Gateway** | Source IP masquerading | Not included |
| **Encryption (IPsec/WireGuard)** | Tunnel encryption | Not applicable |
| **FQDN Policy** | DNS-aware policy via proxy | Not included |
| **Envoy/L7 Proxy** | HTTP-aware load balancing | Not included |
| **Bandwidth Manager** | EDT-based rate limiting | Not applicable |
| **XDP** | Early packet drop/redirect | Not applicable (CNC handles in-kernel) |
| **NodePort** | External traffic LB on each node | Not yet (ClusterIP only) |
| **Session Affinity** | Client IP stickiness | Config present but not fully wired |
| **Maglev** | Consistent hashing for backends | Config present but not used |
| **Health Checking** | Backend health probes | Not implemented |
| **Source Ranges** | LoadBalancer IP allowlists | Not tracked |
| **Socket LB** | cgroup eBPF socket-level LB | Not applicable |
| **Metrics/Prometheus** | BPF map-based metrics | Not included |
| **REST API** | cilium CLI inspection | Not included |
| **KVStore (etcd)** | Shared state across nodes | Not included |

### 6.3 Simplified (Partial implementation)

| Feature | Linux (Full) | Windows (Simplified) |
|---------|-------------|---------------------|
| Backend tracking | Rich state: orphan detection, per-frontend sets, quarantine | Simple count per frontend |
| ID restoration | Restores IDs from BPF maps on restart | Fresh allocation each run |
| Service types | ClusterIP, NodePort, LoadBalancer, HostPort, ExternalName | ClusterIP only |
| Multi-slot reconciliation | Slot-based update for consistency | Direct full-replace via `UpdateServiceBackends` |
| Prune/GC | Full BPF map scan + orphan deletion | No-op (agent owns all state) |

---

## 7. Key Design Decisions

### 7.1 Why build tags instead of interfaces?

The Linux code uses 50+ packages with deep interdependencies. Abstracting all of them behind interfaces would require a massive refactor of upstream Cilium. Build tags allow the Windows port to **compile** without modifying Linux code paths, keeping the diff surgical.

### 7.2 Why stubs instead of conditional compilation within files?

Many Linux files import packages that don't exist on Windows (e.g., `golang.org/x/sys/unix`, `github.com/vishvananda/netlink`). Even a single import of these packages makes the file uncompilable on Windows. File-level build tags are the only option.

### 7.3 Why a separate reconciler instead of reusing BPFOps?

`BPFOps` makes assumptions about the datapath:
- Slot-based map updates (slot 0 = master, slots 1-N = backends)
- RevNat map as separate entity
- Maglev lookup tables
- Source range maps
- Wildcard/NodePort address expansion

CNC has a fundamentally different API model:
- `CreateService` + `UpdateServiceBackends` (atomic backend swap)
- RevNat handled internally by CNC
- No slot concept — backends are a flat list per service

A separate `CNCOps` is cleaner than trying to adapt `BPFOps` to a different paradigm.

### 7.4 Why in-memory tracking in CNCLBMaps?

The reconciler calls `DumpService`/`DumpBackend` for state comparison. Since CNC doesn't expose a "list all entries" API, `CNCLBMaps` maintains in-memory mirrors of what was written. This is safe because only one agent instance owns the CNC state.

---

## 8. Build Instructions

```powershell
# From repository root
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o cilium-agent.exe ./daemon/
```

See `WINDOWS_BUILD.md` for full details including cross-compilation from Linux.

---

## 9. Runtime Requirements

- Windows Server 2019+ with CNC DLL installed (`cnc.sys` driver loaded)
- Kubernetes node with kubeconfig at `C:\k\config` or `KUBERNETES_SERVICE_HOST` env var set
- RBAC permissions: get/list/watch on services, endpoints, endpointslices, pods, nodes (see `install/windows/rbac.yaml`)

---

## 10. Future Work

1. **NodePort support** — Extend CNCOps to handle NodePort service type
2. **Network Policy** — Wire identity allocation + policymap via CNC policy APIs
3. **Health checking** — Backend health probes for quarantine support
4. **Metrics** — Prometheus metrics for LB operations
5. **Graceful restart** — ID restoration from CNC state to avoid backend flapping
6. **CLI flags** — Register hive flags in Windows `NewAgentCmd()` for `--k8s-kubeconfig-path` etc.

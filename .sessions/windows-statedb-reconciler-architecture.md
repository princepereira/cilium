# Session: Windows StateDB Reconciler Architecture

**Date**: 2026-05-27 to 2026-06-02
**Goal**: Port Windows Cilium agent from direct K8sWatcher→CNC to proper Watcher→Store→Reconciler pattern
**Session ID**: `54b865db-02da-4d08-8097-9449bf93fd6c`
**Resume**: `/resume 54b865db-02da-4d08-8097-9449bf93fd6c`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        K8s API Server                                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  K8s Reflector (pkg/loadbalancer/reflectors/k8s.go)                 │
│  • Watches Services + EndpointSlices via informers                  │
│  • Shared code with Linux (removed //go:build !windows)             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ UpsertFrontend / UpsertBackends
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  StateDB Tables                                                     │
│  • statedb.Table[*Frontend]  — service VIPs + metadata              │
│  • statedb.Table[*Backend]   — pod endpoints                        │
│  • statedb.Table[*Service]   — service metadata                     │
│  • Persistent/immutable tree — lazy iterators remain valid           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Change notifications (reconciler.Register)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CNC Reconciler (pkg/loadbalancer/reconciler/reconciler_windows.go) │
│  • CNCOps implements reconciler.Operations[*Frontend]               │
│  • Update: allocate IDs → sortedBackends → upsertBackend per BE     │
│            → UpdateService(slot>0) per BE → UpdateService(slot=0)   │
│  • Delete: delete slots → delete master → release IDs               │
│  • Uses idAllocator[ServiceID] and idAllocator[BackendID]           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ LBMaps interface calls
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CNCLBMaps (pkg/loadbalancer/maps/lbmaps_windows.go)                │
│  • Translates slot-based BPF map writes to CNC API calls            │
│  • Converts network byte order → host byte order (ToHost())         │
│  • Slot batching: slots 1..N accumulate backend IDs,                │
│    slot 0 triggers CreateService + UpdateServiceBackends             │
│  • Handles ERROR_ALREADY_EXISTS via delete-then-recreate             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ CNC API calls
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CNC Shim (cncshim/pkg/cncapi)                                      │
│  • DLL proc calls to CNC API (bpf_sock.sys eBPF framework)          │
│  • CreateLoadBalancerService / DeleteLoadBalancerService             │
│  • CreateLoadBalancerBackends / DeleteLoadBalancerBackends           │
│  • UpdateLoadBalancerServiceBackends                                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Windows eBPF Maps                                                   │
│  • cilium_lb4_services — frontend VIP → service config + BE count   │
│  • cilium_lb4_backends — backend ID → pod IP:port                   │
│  • Queried via: ebpf_state.exe show loadbalancers                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Files Created/Modified

### 1. `pkg/loadbalancer/reconciler/reconciler_windows.go` (NEW)
- Windows CNC-based reconciler implementing `reconciler.Operations[*loadbalancer.Frontend]`
- `CNCOps` struct with `Update`, `Delete`, `Prune` methods
- `SocketTerminationCell` — no-op module (description: `"Socket termination - no-op on Windows"`)
- `Cell` — module `"loadbalancer-reconciler"` with description `"Load-balancing CNC reconciliation for Windows"`
- `newCNCOps(params)` — injects `LBMaps`, `*slog.Logger`, `statedb.Table[*Backend]`
- `newCNCReconciler` — waits for `w.Frontends().Initialized()`, registers StateDB reconciler via `reconciler.Register`
- `Update` flow: allocate service ID → sortedBackends(fe) → for each backend: upsertBackend + UpdateService(slot>0) → UpdateService(slot=0, master)
- `Delete` flow: delete all slots → delete master → release IDs
- `sortedBackends(fe)` — iterates `fe.Backends` (lazy `iter.Seq2`), sorts active-first then by address
- `upsertBackend` — creates `Backend4V3`/`Backend6V3`, calls `LBMaps.UpdateBackend`
- Uses `idAllocator[ServiceID]` and `idAllocator[BackendID]` for numeric ID allocation
- Build tag: `//go:build windows`

### 2. `pkg/loadbalancer/maps/lbmaps_windows.go` (MODIFIED)
- Translates slot-based BPF map semantics to CNC API calls
- `CNCLBMaps` struct with:
  - `pendingSlots map[string][]uint32` — accumulates backend IDs for slots 1..N
  - `cncBackends map[uint16][]cncapi.BackendInfo` — tracks what CNC currently has per service
  - `createdServices map[uint16]bool` — prevents duplicate service creation
- `UpdateService` logic:
  - Slot > 0: accumulates backend ID in pendingSlots (slot 1 clears previous pending)
  - Slot 0 (master): creates service via `CreateLoadBalancerService` (if not created), reads pendingSlots, calls `UpdateLoadBalancerServiceBackends(serviceID, lbInfo, newBackends, oldBackends)`
- `UpdateBackend`: stores locally + calls `CreateLoadBalancerBackends`
- `DeleteService`: on master slot deletion calls `DeleteLoadBalancerService`
- `DeleteBackend`: calls `DeleteLoadBalancerBackends`
- `SetAPI(interface{})` — runtime injection of CNC API (avoids import cycle)
- Build tag: `//go:build windows`

### 3. `pkg/loadbalancer/maps/cell_windows.go` (MODIFIED)
- Module: `"loadbalancer-maps"`, `"Load-balancing CNC maps for Windows"`
- Provides `newCNCLBMaps`
- Build tag: `//go:build windows`

### 4. `pkg/loadbalancer/reflectors/stub_windows.go` (MODIFIED)
- Provides `Cell` (wrapping `K8sReflectorCell` + `FileReflectorCell` + `NetnsCookieSupportFunc`)
- `FileReflectorCell` — no-op
- `NetnsCookieSupportFunc` — always returns false
- K8s reflector is REAL (shared code from `k8s.go`)
- Build tag: `//go:build windows`

### 5. `pkg/loadbalancer/reflectors/k8s.go` (MODIFIED)
- **Removed** `//go:build !windows` — now compiles on Windows
- Added debug logging: `newEventStream`, `RegisterK8sReflector`, `runServiceEndpointsReflector`, buffer processing

### 6. `pkg/loadbalancer/reflectors/conversions.go` (MODIFIED)
- **Removed** `//go:build !windows`

### 7. `pkg/loadbalancer/reflectors/metrics.go` (MODIFIED)
- **Removed** `//go:build !windows`

### 8. `pkg/loadbalancer/reconciler/bpf_reconciler.go` (MODIFIED)
- Added `//go:build !windows` (Linux-only)

### 9. `pkg/loadbalancer/reconciler/cell.go` (MODIFIED)
- Added `//go:build !windows` (Linux BPF reconciler cell)

### 10. `pkg/loadbalancer/reconciler/cmds.go` (MODIFIED)
- Added `//go:build !windows`

### 11. `pkg/loadbalancer/reconciler/termination.go` (MODIFIED)
- Added `//go:build !windows`

### 12. `daemon/cmd/windows_stubs.go` (MODIFIED)
- Full Windows Agent hive cell definition:
```go
var Agent = cell.Module("agent", "Cilium Agent Windows",
    winDatapath.Cell,                          // CNCClient
    client.Cell,                               // K8s clientset
    cell.Provide(node.NewNopLocalNodeSynchronizer),
    cell.Config(cmtypes.DefaultClusterInfo),
    node.LocalNodeStoreCell,
    cell.Provide(func() *option.DaemonConfig {
        return &option.DaemonConfig{EnableIPv4: true, EnableIPv6: true}
    }),
    cell.Provide(source.NewSources),
    cell.Provide(tables.NewNodeAddressTable, statedb.RWTable[tables.NodeAddress].ToTable),
    cell.Provide(k8stables.NewPodTableAndReflector),
    cell.Config(k8s.DefaultConfig),
    cell.Provide(k8s.DefaultServiceWatchConfig),
    kpr.Cell,
    nodeipamconfig.Cell,
    lbipamconfig.Cell,
    maglev.Cell,
    loadbalancer.ConfigCell,
    writer.Cell,
    reflectors.Cell,
    maps.Cell,
    reconciler.Cell,
    cell.Invoke(wireCNCClientToLBMaps),
)
```
- `wireCNCClientToLBMaps` — lifecycle hook that waits for `client.Ready()` then injects API via `SetAPI`

---

## Key Design Decisions

1. **Hive module descriptions**: Only `[a-zA-Z0-9_\- ]{1,80}` — no parentheses
2. **Import cycle avoidance**: `CNCLBMaps.SetAPI(interface{})` accepts `interface{}` cast to `cncapi.CNCApi`
3. **Slot batching**: CNCOps writes slots 1..N (each slot = one backend ID), then slot 0 (master with count). CNCLBMaps accumulates slot>0 backend IDs in `pendingSlots` and flushes them as `UpdateLoadBalancerServiceBackends` when slot 0 arrives.
4. **CNC API retry**: `wireCNCClientToLBMaps` uses background goroutine waiting on `client.Ready()` channel — CNC API may not be available immediately at startup
5. **Lazy backend iterator**: `fe.Backends` is `iter.Seq2[*Backend, Revision]` captured during `refreshFrontend` WriteTxn — iterating it later still works because StateDB uses persistent/immutable trees
6. **No Maglev on Windows**: CNCOps doesn't compute Maglev tables (backends are managed by CNC directly)
7. **Byte-order convention**: LBMaps interface expects network byte order (matching BPF). CNCLBMaps calls `.ToHost()` before extracting port/address for CNC API. IP addresses (byte arrays) are NOT affected — only ports are byte-swapped.
8. **Stale backend handling**: On agent restart, backend IDs may collide with CNC entries from previous run. Fix: delete old entry → recreate with correct IP/port. Address family determined from `addr.Is6()` (AF_INET=2, AF_INET6=23).

---

## Current Status (2026-06-02)

### ✅ Working End-to-End
- Agent starts, connects to K8s API and CNC API (with retry on CNC init failure)
- K8s reflector processes Service/EndpointSlice events into StateDB
- Reconciler triggers `CNCOps.Update` for each Frontend change
- `fe.Backends` lazy iterator correctly yields backends
- `CreateLoadBalancerService` succeeds with correct ports (host byte order)
- `CreateLoadBalancerBackends` succeeds (with delete-recreate for stale entries)
- `UpdateLoadBalancerServiceBackends` — confirmed working with standalone test (serviceID=1)
- Services visible in eBPF maps via `ebpf_state.exe show loadbalancers`

### ✅ Bugs Fixed This Session
1. **Empty backends** — confirmed lazy `iter.Seq2` pattern is valid (StateDB immutable trees)
2. **ERROR_ALREADY_EXISTS (0x800700B7)** — services: skip if exists; backends: delete stale + recreate
3. **Byte-order bug** — CNC API expects host byte order; added `ToHost()` on ServiceKey and BackendValue
4. **Stale backend IPs** — on agent restart, old backend IDs in CNC had wrong IPs; fixed with delete-then-recreate pattern
5. **Repeated reconciliation loop** — was caused by errors in backend creation preventing "done" status
6. **ServiceID byte-order** — `value.GetRevNat()` returns network-order; fixed with `byteorder.NetworkToHost16()` conversion
7. **CNC reinitialization wipes LB maps** — removed `Close()+New()` cycle from `CNCClient.Start()` that was destroying active LB rules

### ⚠️ Known Issues
1. **Stale CNC state from old runs** — Previous runs with wrong serviceIDs (256, 512, etc.) leave stale entries; needs cleanup before fresh agent start
2. **`--k8s-kubeconfig-path` flag not registered** — Windows `NewAgentCmd()` doesn't call `h.RegisterFlags(cmd.Flags())`; workaround: set `$env:KUBERNETES_SERVICE_HOST` env var

### 🔲 Remaining Work
1. Register hive flags in Windows `NewAgentCmd()` for proper CLI flag support
2. Remove excessive debug/diagnostic logging (keep essential INFO logs)
3. Remove dead code: `pkg/datapath/win/k8s_watcher.go`
4. Test pod scale up/down (dynamic backend changes)
5. Test service deletion flow
6. Consider cleanup of stale services on agent startup (full reconciliation)
7. Add NodePort support
8. Add Network Policy support via CNC policy APIs

---

## Documentation

- `docs/windows-port-design.md` — Comprehensive design doc (build tags, omitted features, data flow comparison)
- `docs/WINDOWS_BUILD.md` — Build instructions
- `docs/windows-datapath-architecture.md` — CNC datapath architecture details
- `docs/windows-datapath-architecture.pdf` — PDF version of architecture doc

---

## Build & Test

```powershell
cd C:\Users\ppereira\Projects\Go\cilium
go build -o cilium-agent.exe ./daemon/cmd
# Copy to target machine and run:
.\cilium-agent.exe

# Filter CNC API logs only:
.\cilium-agent.exe 2>&1 | Select-String -Pattern "CNC (Create|Update|Delete)LoadBalancer|recreated|Frontend reconciled"

# Verify eBPF map state:
ebpf_state.exe show loadbalancers filter <ClusterIP>
```

---

## What's Left To Do

1. ~~Fix the `CreateLoadBalancerBackends` error~~ ✅ Fixed (byte-order + already-exists handling)
2. ~~Verify end-to-end: service creation + backend association~~ ✅ Working
3. ~~Fix the repeated reconciliation loop~~ ✅ Fixed (errors prevented reconciliation completion)
4. ~~Fix stale backend IPs on restart~~ ✅ Fixed (delete-then-recreate pattern)
5. ~~Fix serviceID byte-order (E_INVALIDARG)~~ ✅ Fixed (`byteorder.NetworkToHost16()`)
6. ~~Fix CNC reinitialize wiping LB maps~~ ✅ Fixed (removed Close+New cycle)
7. Register hive flags in Windows `NewAgentCmd()` for `--k8s-kubeconfig-path` support
8. Remove dead code: `pkg/datapath/win/k8s_watcher.go`
9. Remove excessive debug/diagnostic logging (keep essential INFO logs)
10. Test pod scale up/down (dynamic backend changes)
11. Test service deletion flow
12. Consider full reconciliation on startup (cleanup orphaned CNC entries)

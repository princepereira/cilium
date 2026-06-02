# Cilium Windows Datapath Architecture

## Overview

The Cilium Windows agent follows the same Watcher → Store → Reconciler pattern as
the Linux agent, using StateDB as the intermediate state store. Kubernetes resources
are watched by reflectors, which populate StateDB tables via the Writer. A CNC
reconciler then observes table changes and programs Windows eBPF maps via the CNC
(Container Networking Compute) API.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Kubernetes API Server                         │
└────────────────┬──────────────────────────────┬─────────────────────┘
                 │ Watch Services                │ Watch EndpointSlices
                 ▼                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         K8s Reflector  (pkg/loadbalancer/reflectors/k8s.go)         │
│                                                                     │
│  Watches K8s Services and EndpointSlices via Informer framework     │
│  Converts K8s objects to Cilium's internal LB model                 │
│  Calls Writer to populate StateDB tables                            │
│                                                                     │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │  writer.Writer.UpsertService()
                                  │  writer.Writer.UpsertBackends()
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         Writer  (pkg/loadbalancer/writer/)                           │
│                                                                     │
│  Translates high-level operations into StateDB table mutations      │
│  Handles Frontend/Backend/Service table writes                      │
│                                                                     │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │  Table inserts/updates
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         StateDB Tables  (pkg/loadbalancer/)                          │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐          │
│  │  Frontend    │  │  Backend     │  │  Service         │          │
│  │  Table       │  │  Table       │  │  Table           │          │
│  └──────────────┘  └──────────────┘  └──────────────────┘          │
│                                                                     │
│  Change notifications propagate to reconciler                       │
│                                                                     │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │  reconciler.Operations[*Frontend]
                                  │  Update() / Delete() / Prune()
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         CNCOps Reconciler                                           │
│         (pkg/loadbalancer/reconciler/reconciler_windows.go)         │
│                                                                     │
│  Implements reconciler.Operations[*Frontend]:                       │
│    • Update(): allocates IDs, writes backend slots 1..N, then       │
│               master slot 0 → triggers CNC service+backend calls    │
│    • Delete(): removes all slots + master entry                     │
│    • Prune():  no-op (CNC state tracked locally)                    │
│                                                                     │
│  Uses idAllocator for stable service/backend IDs                    │
│  Sorts backends by state then address for determinism               │
│                                                                     │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │  maps.LBMaps interface
                                  │  UpdateService() / UpdateBackend()
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         CNCLBMaps  (pkg/loadbalancer/maps/lbmaps_windows.go)        │
│                                                                     │
│  Implements maps.LBMaps interface — translates slot-based BPF       │
│  map operations into CNC API calls:                                 │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Slot Batching Logic:                                         │   │
│  │    • Slot > 0: buffers backendID in pendingSlots map          │   │
│  │    • Slot 0 (master): triggers actual CNC API calls:          │   │
│  │      1. CreateLoadBalancerService (if first time)             │   │
│  │      2. CreateLoadBalancerBackends (for new backends)         │   │
│  │      3. UpdateLoadBalancerServiceBackends (swap old→new)      │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Tracks CNC state: createdServices, cncBackends, pendingSlots       │
│                                                                     │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │  cncapi.CNCApi interface
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         CNCClient  (pkg/datapath/win/client.go)                     │
│                                                                     │
│  Wraps cncshim CNCApi interface with lifecycle management           │
│  Retries initialization every 5s until cncapi.dll is ready          │
│  Exposes Ready() channel and API() method                           │
│                                                                     │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │  API() → cncapi.CNCApi
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         cncshim  (github.com/princepereira/cncshim)                 │
│         pkg/cncapi/client.go                                        │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  CNCApi Interface:                                         │     │
│  │    • CreateLoadBalancerBackends([]BackendInfo)              │     │
│  │    • CreateLoadBalancerService(serviceID, *LBInfo)          │     │
│  │    • UpdateLoadBalancerServiceBackends(id, info, new, old)  │     │
│  │    • DeleteLoadBalancerService(serviceID, *LBInfo)          │     │
│  │    • DeleteLoadBalancerBackends(af, []backendIDs)           │     │
│  │    • GetLoadBalancerBackends(af, []backendIDs)              │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                     │
│  Loads cncapi.dll via syscall (LazyDLL)                             │
│  Converts Go structs → ABI structs (C-compatible layout)            │
│  Calls exported C functions: CncInitialize, CncCreateLB..., etc.    │
│                                                                     │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  │  DLL syscall
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│         cncapi.dll  (Native Windows DLL)                            │
│         Talks to eBPF maps via ebpfapi.dll / eBPF drivers           │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  Windows eBPF Maps (kernel):                               │     │
│  │    • LB Frontend Map  (Service VIP → Backend set)          │     │
│  │    • LB Backend Map   (Backend ID → IP:Port)               │     │
│  │    • CT (Connection Tracking) Map                          │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Hive / Dependency Injection (daemon/cmd/windows_stubs.go)

The agent is bootstrapped using Cilium's **Hive** framework for dependency injection.
The following cells are registered:

| Cell                    | Module ID                     | Purpose                                      |
|------------------------|-------------------------------|----------------------------------------------|
| `winDatapath.Cell`      | `datapath-win`                | Provides `CNCClient` (cncshim connection)   |
| `loadbalancer.ConfigCell` | `loadbalancer-config`       | LB configuration parameters                  |
| `writer.Cell`           | `loadbalancer-writer`         | Populates StateDB from reflector calls       |
| `reflectors.Cell`       | `loadbalancer-reflectors`     | K8s Service/EndpointSlice reflectors         |
| `maps.Cell`             | `loadbalancer-maps`           | Provides CNCLBMaps (LBMaps interface)        |
| `reconciler.Cell`       | `loadbalancer-reconciler`     | CNCOps reconciler for StateDB → CNC         |

A lifecycle hook (`wireCNCClientToLBMaps`) connects the CNCClient API to CNCLBMaps
at startup, once the DLL is ready.

### 2. K8s Reflector (pkg/loadbalancer/reflectors/k8s.go)

**Role**: Watches Kubernetes Services and EndpointSlices. Shared with Linux.

- Uses `pkg/k8s/resource.Resource[T]` informers for watch/list
- Converts K8s objects to Cilium's internal model via `convertService()` / `convertEndpoints()`
- Calls `writer.Writer` to insert/update/delete StateDB table entries
- No direct datapath calls — purely a data translator

### 3. Writer (pkg/loadbalancer/writer/)

**Role**: Accepts high-level LB mutations and writes to StateDB tables.

- `UpsertService()`: Creates/updates Frontend + Service entries
- `UpsertBackends()`: Creates/updates Backend entries, associates with Frontends
- `DeleteService()` / `DeleteBackends()`: Removes entries
- Triggers StateDB change notifications consumed by the reconciler

### 4. StateDB Tables (pkg/loadbalancer/)

**Role**: Central state store (Cilium's equivalent of an in-memory database).

| Table       | Key                  | Contents                          |
|-------------|---------------------|-----------------------------------|
| `Frontend`  | L3n4Addr (VIP:Port) | Service type, flags, backends     |
| `Backend`   | L3n4Addr (Pod IP)   | State (active/terminating/maint.) |
| `Service`   | ServiceName          | Metadata, annotations             |

StateDB provides:
- **Consistent snapshots** via read transactions
- **Change notifications** that trigger reconciliation
- **Initialized signals** for startup sequencing

### 5. CNCOps Reconciler (pkg/loadbalancer/reconciler/reconciler_windows.go)

**Role**: Observes Frontend table changes and programs CNC via LBMaps interface.

Implements `reconciler.Operations[*Frontend]`:

**Update(fe)** — Called when a Frontend is created or modified:
1. Allocate/lookup service ID via `idAllocator`
2. Iterate `fe.Backends` (sorted: active first, then by address)
3. For each backend: allocate backend ID, call `LBMaps.UpdateBackend()`
4. Write service slot entries (slot 1..N with backendIDs)
5. Write master entry (slot 0 with count) → triggers CNC association

**Delete(fe)** — Called when a Frontend is removed:
1. Delete all slot entries (N..1)
2. Delete master entry (slot 0) → triggers CNC service deletion
3. Release service ID

**Prune()** — No-op (CNC state tracked in CNCLBMaps)

### 6. CNCLBMaps (pkg/loadbalancer/maps/lbmaps_windows.go)

**Role**: Translates slot-based BPF map operations into CNC API calls.

This is the **critical translation layer** between Cilium's Linux-oriented LBMaps
interface and the Windows CNC API.

#### Slot Batching Model

The Linux BPF map model writes:
- Slot 1..N first (each contains a backendID)
- Slot 0 last (master entry with backend count)

CNCLBMaps buffers these and issues CNC calls when slot 0 arrives:

```
UpdateService(slot=1, backendID=100) → pendingSlots[svcKey] = [100]
UpdateService(slot=2, backendID=200) → pendingSlots[svcKey] = [100, 200]
UpdateService(slot=0, count=2)       → triggers:
  1. CreateLoadBalancerService(serviceID, lbInfo)     [if first time]
  2. CreateLoadBalancerBackends([{ID:100}, {ID:200}]) [new backends]
  3. UpdateLoadBalancerServiceBackends(id, info,      [swap]
       newBackends=[100,200], oldBackends=[...])
```

#### State Tracking

| Map               | Purpose                                              |
|-------------------|------------------------------------------------------|
| `pendingSlots`    | Accumulates backendIDs from slot > 0 writes          |
| `cncBackends`     | Tracks what CNC currently has (for swap semantics)   |
| `createdServices` | Prevents duplicate CreateLoadBalancerService calls   |

### 7. CNCClient (pkg/datapath/win/client.go)

**Role**: Manages the connection to cncshim (cncapi.dll).

- On `Start()`: calls `cncapi.New()` which loads `cncapi.dll` and calls `CncInitialize`
- If initialization fails (DLL not ready), retries every 5 seconds in background
- Exposes `Ready()` channel and `API()` method returning `cncapi.CNCApi` interface
- CNCLBMaps receives the API via `SetAPI()` once Ready() fires

### 8. cncshim Library (vendor/github.com/princepereira/cncshim)

**Role**: Go bindings for the CNC API DLL.

**Architecture**:
- `pkg/cncapi/cnciface.go` — Defines `CNCApi` interface
- `pkg/cncapi/client.go` — Implementation using `syscall.LazyDLL`
- `pkg/cncapi/abi_types.go` — C-compatible struct definitions
- `pkg/cncapi/abi_convert.go` — Go ↔ ABI conversion functions

**DLL calling convention**:
```
Go struct (BackendInfo) → ABI struct (abiBackendInfo) → syscall.Call → cncapi.dll → eBPF map
```

## CNC API Call Flow (Complete Example)

When a new pod endpoint is discovered:

```
K8s API Server
    │
    │  EndpointSlice event (Added: pod 10.244.1.84:80)
    ▼
K8s Reflector (reflectors/k8s.go)
    │
    │  convertEndpoints() → writer.UpsertBackends()
    ▼
StateDB Frontend Table (updated: new backend in fe.Backends)
    │
    │  Change notification
    ▼
CNCOps.Update(fe)
    │  1. serviceID = idAllocator.acquireLocalID(fe.Address)
    │  2. backendID = idAllocator.acquireLocalID(be.Address)
    │  3. LBMaps.UpdateBackend(backendKey, backendVal)
    │  4. LBMaps.UpdateService(slot=1, backendID)   ← buffered
    │  5. LBMaps.UpdateService(slot=0, count=1)     ← triggers CNC
    ▼
CNCLBMaps.UpdateService(slot=0)
    │  1. CreateLoadBalancerService(serviceID, lbInfo)
    │  2. CreateLoadBalancerBackends([{ID:backendID, IP:10.244.1.84, Port:80}])
    │  3. UpdateLoadBalancerServiceBackends(serviceID, lbInfo, [new], [old])
    ▼
CNCClient.API() → cncapi.CNCApi interface
    │
    │  Go struct → ABI struct → proc.Call(...)
    ▼
cncapi.dll → ebpfapi.dll → eBPF Maps updated
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| StateDB as intermediate store | Decouples K8s watching from datapath programming; enables retry/reconciliation |
| Slot batching in CNCLBMaps | CNC API is not slot-based; must accumulate slots then issue one API call |
| Swap semantics for UpdateServiceBackends | API requires full old+new sets, not incremental delta |
| ID allocator (not hash-based) | Reconciler manages IDs centrally; CNCLBMaps doesn't need to know about K8s UIDs |
| Shared K8s reflector with Linux | Same code watches K8s; only reconciler+maps differ per platform |
| `SetAPI(interface{})` injection | Avoids import cycle between maps and datapath/win packages |

## Comparison: Linux vs Windows Datapath

| Layer           | Linux                           | Windows                          |
|----------------|--------------------------------|----------------------------------|
| Reflector       | Same (reflectors/k8s.go)       | Same (reflectors/k8s.go)        |
| Writer          | Same (writer/)                  | Same (writer/)                   |
| StateDB         | Same (loadbalancer/)            | Same (loadbalancer/)             |
| Reconciler      | BPFOps (bpf_reconciler.go)     | CNCOps (reconciler_windows.go)  |
| Maps interface  | BPF maps (lbmaps_linux.go)     | CNCLBMaps (lbmaps_windows.go)  |
| Datapath        | eBPF programs in kernel         | cncapi.dll → ebpfapi.dll        |

## File Map

```
daemon/
  cmd/
    windows_stubs.go       ← Agent cell definition, wireCNCClientToLBMaps

pkg/loadbalancer/
  config.go                ← ConfigCell: LB configuration
  tables.go                ← Frontend/Backend/Service table definitions

pkg/loadbalancer/writer/
  writer.go                ← Writer: translates ops to StateDB writes

pkg/loadbalancer/reflectors/
  k8s.go                   ← K8s Service/EndpointSlice reflector (shared)
  conversions.go           ← K8s → Cilium model conversions (shared)
  metrics.go               ← Reflector metrics (shared)
  stub_windows.go          ← Windows stubs: FileReflectorCell, NetnsCookie

pkg/loadbalancer/maps/
  lbmaps_windows.go        ← CNCLBMaps: slot batching → CNC API calls
  cell_windows.go          ← Maps cell for Windows

pkg/loadbalancer/reconciler/
  reconciler_windows.go    ← CNCOps: StateDB → LBMaps reconciliation
  bpf_reconciler.go        ← Linux BPFOps (build tag: !windows)
  cell.go                  ← Linux cell (build tag: !windows)

pkg/datapath/win/
  client.go                ← CNCClient: lifecycle, retry, cncshim connection
  ARCHITECTURE.md          ← This file

vendor/github.com/princepereira/cncshim/
  pkg/cncapi/
    cnciface.go            ← CNCApi interface definition
    client.go              ← DLL-backed implementation
    abi_types.go           ← C-compatible struct layouts
    types.go               ← Public Go types (BackendInfo, LoadBalancerInfo, etc.)
```

## Which Component Imports and Uses cncshim?

**`pkg/loadbalancer/maps/lbmaps_windows.go`** (CNCLBMaps) is the component that
imports and uses the `cncapi.CNCApi` interface to make CNC API calls that update
Windows eBPF maps.

The import/call chain:
```
CNCOps (reconciler) → LBMaps interface → CNCLBMaps → cncapi.CNCApi → cncapi.dll → eBPF maps
```

The CNCApi interface is injected into CNCLBMaps at runtime via `SetAPI()`, which is
called by `wireCNCClientToLBMaps()` in `daemon/cmd/windows_stubs.go` once the
CNCClient reports Ready.

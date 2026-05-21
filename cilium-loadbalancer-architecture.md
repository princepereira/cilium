# Cilium Loadbalancer Architecture

## Overview

The Cilium loadbalancer is not a standalone binary — it's a **Hive cell** (dependency injection module) integrated into the Cilium agent daemon. The agent uses the Hive framework for dependency injection and lifecycle management.

---

## Entry Point: Daemon Main

**File:** `daemon/main.go`

```go
func main() {
    hiveFn := func() *hive.Hive {
        return hive.New(cmd.Agent)
    }
    cmd.Execute(cmd.NewAgentCmd(hiveFn))
}
```

---

## Call Chain: Daemon → Loadbalancer

```
daemon/main.go
  └─ hive.New(cmd.Agent)
       └─ cmd.Agent (cell.Module "agent")          ← daemon/cmd/cells.go
            ├─ Infrastructure
            ├─ ControlPlane
            │    └─ loadbalancer_cell.Cell           ← line 254
            └─ datapath.Cell
```

### Agent Module (`daemon/cmd/cells.go`)

```go
var Agent = cell.Module(
    "agent",
    "Cilium Agent",
    Infrastructure,
    ControlPlane,
    datapath.Cell,
)
```

### ControlPlane Module (`daemon/cmd/cells.go`)

The `ControlPlane` module includes the loadbalancer cell:

```go
// Control-plane for configuring service load-balancing
loadbalancer_cell.Cell,
```

Import:
```go
loadbalancer_cell "github.com/cilium/cilium/pkg/loadbalancer/cell"
```

---

## Loadbalancer Cell Structure

**File:** `pkg/loadbalancer/cell/cell.go`

```go
var Cell = cell.Group(
    loadbalancer.ConfigCell,        // Configuration
    writer.Cell,                    // Tables + Writer API
    reflectors.Cell,                // K8s/KVStore → LB Tables
    maps.Cell,                      // BPF Map Wrappers
    reconciler.Cell,                // Tables → BPF Maps
    redirectpolicy.Cell,            // CiliumLocalRedirectPolicy
    healthserver.Cell,              // HealthCheckNodePort
    newServiceRestApiHandler,       // REST API handler
    newInitWaitFunc,                // Init synchronization
)
```

### Sub-components

| Component | Package | Purpose |
|-----------|---------|---------|
| ConfigCell | `pkg/loadbalancer` | LB configuration flags |
| writer.Cell | `pkg/loadbalancer/writer` | StateDB table write API |
| reflectors.Cell | `pkg/loadbalancer/reflectors` | Syncs K8s/KVStore state → LB tables |
| maps.Cell | `pkg/loadbalancer/maps` | BPF map wrappers |
| reconciler.Cell | `pkg/loadbalancer/reconciler` | Reconciles tables → BPF maps |
| redirectpolicy.Cell | `pkg/loadbalancer/redirectpolicy` | CiliumLocalRedirectPolicy |
| healthserver.Cell | `pkg/loadbalancer/healthserver` | HealthCheckNodePort |

---

## Data Flow

```
K8s Services/Endpoints
        │
        ▼
   reflectors.Cell          (watches K8s resources)
        │
        ▼
   StateDB Tables           (frontends, backends, services)
        │
        ▼
   reconciler (BPFOps)      (detects changes, computes diff)
        │
        ▼
   LBMaps interface         (abstraction over BPF maps)
        │
        ▼
   bpf.Map.Update()         (kernel syscall to update eBPF map)
        │
        ▼
   Linux Kernel eBPF Maps   (used by datapath for packet processing)
```

---

## BPF Map Operations

### Interface: `LBMaps` (`pkg/loadbalancer/maps/lbmaps.go`)

The `LBMaps` interface (~line 113) is a composition of sub-interfaces:

```go
type LBMaps interface {
    serviceMaps      // UpdateService / DeleteService / DumpService
    backendMaps      // UpdateBackend / DeleteBackend / DumpBackend
    revNatMaps       // UpdateRevNat / DeleteRevNat / DumpRevNat
    affinityMaps     // UpdateAffinityMatch / DeleteAffinityMatch
    sourceRangeMaps  // UpdateSourceRange / DeleteSourceRange
    maglevMaps       // UpdateMaglev / DeleteMaglev
    sockRevNatMaps   // UpdateSockRevNat / DeleteSockRevNat
    IsEmpty() bool
}
```

### Implementation: `BPFLBMaps`

`BPFLBMaps` (~line 125) is the concrete implementation that performs actual kernel writes:

| Method | ~Line | Underlying BPF Map |
|--------|-------|--------------------|
| `UpdateService` | L565 | `service4Map` / `service6Map` |
| `UpdateBackend` | L553 | `backend4Map` / `backend6Map` |
| `UpdateRevNat` | L481 | `revNat4Map` / `revNat6Map` |
| `UpdateAffinityMatch` | L588 | `affinityMatchMap` |
| `UpdateSourceRange` | L615 | `sourceRange4Map` / `sourceRange6Map` |
| `UpdateMaglev` | L627 | Inner maps via `ebpf` package |
| `UpdateSockRevNat` | L709 | `sockRevNat4Map` / `sockRevNat6Map` |

---

## Reconciler: `BPFOps` (`pkg/loadbalancer/reconciler/bpf_reconciler.go`)

The reconciler decides **when** to write to BPF maps by watching StateDB for changes.

```go
type BPFOps struct {
    LBMaps maps.LBMaps
    // ...
}
```

### Key Write Points

| Operation | ~Line | Call |
|-----------|-------|------|
| Update service entry | L1167 | `ops.LBMaps.UpdateService(svcKey, svcVal)` |
| Update backend | L1235 | `ops.LBMaps.UpdateBackend(...)` |
| Update revNAT | L1281 | `ops.LBMaps.UpdateRevNat(...)` |
| Update affinity match | L1261 | `ops.LBMaps.UpdateAffinityMatch(...)` |
| Update source range | L1021 | `ops.LBMaps.UpdateSourceRange(...)` |
| Update maglev | L1305 | `ops.LBMaps.UpdateMaglev(...)` |
| Delete service | L464 | `ops.LBMaps.DeleteService(...)` |
| Delete backend | L586 | `ops.LBMaps.DeleteBackend(...)` |
| Delete revNAT | L470 | `ops.LBMaps.DeleteRevNat(...)` |
| Delete maglev | L416 | `ops.LBMaps.DeleteMaglev(...)` |

---

## Standalone Tools

Two standalone binaries exist for development/debugging (they do NOT run in production):

| Tool | Path | Purpose |
|------|------|---------|
| REPL | `pkg/loadbalancer/repl/main.go` | Interactive shell for inspecting LB state |
| Benchmark | `pkg/loadbalancer/benchmark/cmd/main.go` | Performance benchmarking |

The REPL reuses the same `loadbalancer_cell.Cell` but with a simplified setup (no full agent).

---

## Why Windows Builds Fail

Cilium cannot be built with `GOOS=windows` because:

1. **eBPF** — Relies on Linux eBPF (kernel feature, no Windows equivalent)
2. **Linux syscalls** — Uses `golang.org/x/sys/unix`, `netlink`, `procfs`, `sysfs`
3. **Build constraints** — Many files have `//go:build linux` tags
4. **CGo** — Some components use C libraries compiled for Linux
5. **Kernel interfaces** — Manages network namespaces, cgroups, iptables

**Solution:** Use WSL2 or cross-compile with `GOOS=linux`.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     daemon/main.go                           │
│                    hive.New(cmd.Agent)                       │
└────────────────────────┬────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
   Infrastructure   ControlPlane    datapath.Cell
                         │
                         ▼
              loadbalancer_cell.Cell
                         │
         ┌───────┬───────┼───────┬──────────┐
         ▼       ▼       ▼       ▼          ▼
      Config  Writer  Reflectors Maps   Reconciler
                 │       │        ▲          │
                 ▼       ▼        │          ▼
              StateDB Tables ─────┘    BPF Map Updates
                                            │
                                            ▼
                                    Linux Kernel eBPF
```

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `daemon/main.go` | Agent entry point |
| `daemon/cmd/cells.go` | Agent module & cell composition |
| `pkg/loadbalancer/cell/cell.go` | LB cell definition |
| `pkg/loadbalancer/maps/lbmaps.go` | BPF map interface & implementation |
| `pkg/loadbalancer/reconciler/bpf_reconciler.go` | StateDB → BPF reconciliation |
| `pkg/loadbalancer/writer/` | StateDB table write API |
| `pkg/loadbalancer/reflectors/` | K8s resource → StateDB sync |
| `pkg/loadbalancer/repl/main.go` | Development REPL tool |

# Cilium Function Mapping: Endpoint & Load-Balancer BPF Map Operations

This document maps each requested operation to the concrete function, file, and line
in the Cilium agent code. The load-balancer entries reflect the current StateDB-based
reconciler (`pkg/loadbalancer`), with the low-level BPF map primitives in
`pkg/loadbalancer/maps/lbmaps.go`.

---

## 1. Create endpoint in a Linux node

| Layer | Function (receiver) | File | Line |
|-------|---------------------|------|------|
| API entry | `CreateEndpoint` (`*EndpointAPIManager`) | `pkg/endpoint/api/endpoint_api_manager.go` | 94 |
| Build from API model | `NewEndpointFromChangeModel` (`*endpointCreator`) | `pkg/endpoint/creator/creator.go` | 110 |
| **Main create + register on node** | `AddEndpoint` (`*endpointManager`) | `pkg/endpointmanager/manager.go` | 798 |
| Expose / allocate ID | `expose` (`*endpointManager`) | `pkg/endpointmanager/manager.go` | 692 |
| Endpoint struct factory | `createEndpoint` (package) | `pkg/endpoint/endpoint.go` | 591 |

**Flow:** `CreateEndpoint` → `NewEndpointFromChangeModel` → `AddEndpoint` → `expose` → `ep.Start(newID)`
(exposes endpoint to `lxcMap` and other subsystems and triggers datapath regeneration).

---

## 2. Delete endpoint from a Linux node

| Layer | Function (receiver) | File | Line |
|-------|---------------------|------|------|
| API entry | `DeleteEndpoint` (`*EndpointAPIManager`) | `pkg/endpoint/api/endpoint_api_manager.go` | 77 |
| **Main remove entry** | `RemoveEndpoint` (`*endpointManager`) | `pkg/endpointmanager/manager.go` | 526 |
| Remove implementation | `removeEndpoint` (`*endpointManager`) | `pkg/endpointmanager/manager.go` | 499 |
| Datapath/BPF cleanup | `Delete` (`*Endpoint`) | `pkg/endpoint/endpoint.go` | 2633 |
| Policy/state cleanup | `leaveLocked` (`*Endpoint`) | `pkg/endpoint/endpoint.go` | 1256 |

**Flow:** `DeleteEndpoint` → `RemoveEndpoint` → `removeEndpoint` → `ep.Delete()` → `ep.leaveLocked()`
(detaches tc BPF programs, deletes per-endpoint maps, releases identity, cleans iptables).

---

## 3. Create frontend service in eBPF maps

| Layer | Function (receiver) | File | Line |
|-------|---------------------|------|------|
| Reconciler upsert | `Update` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 725 |
| Upsert service slot | `upsertService` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 1197 |
| Upsert master slot (slot 0) | `upsertMaster` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 1218 |
| **Low-level map write** | `UpdateService` (`*BPFLBMaps`) | `pkg/loadbalancer/maps/lbmaps.go` | 565 |

Writes to `cilium_lb4_services` / `cilium_lb6_services`.

---

## 4. Create backends in eBPF maps

| Layer | Function (receiver) | File | Line |
|-------|---------------------|------|------|
| Reconciler upsert | `upsertBackend` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 1250 |
| **Low-level map write** | `UpdateBackend` (`*BPFLBMaps`) | `pkg/loadbalancer/maps/lbmaps.go` | 553 |

Writes to `cilium_lb4_backends` / `cilium_lb6_backends`.

---

## 5. Update / associate backend to a service in eBPF maps

| Layer | Code / Function (receiver) | File | Line |
|-------|----------------------------|------|------|
| Slot association | `svcKey.SetBackendSlot(slot)` + `svcVal.SetBackendID(beID)` + `upsertService(...)` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 970–990 |
| Low-level map write | `UpdateService` (`*BPFLBMaps`) | `pkg/loadbalancer/maps/lbmaps.go` | 565 |

Each backend occupies a service slot (1..N); slot 0 is the master holding backend counts.
The kernel BPF datapath indexes these slots to load-balance traffic.

---

## 6. Delete frontend service from eBPF maps

| Layer | Function (receiver) | File | Line |
|-------|---------------------|------|------|
| Reconciler delete | `Delete` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 342 |
| Orchestrate frontend delete | `deleteFrontend` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 422 |
| Delete service slot | `deleteService` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 1213 |
| **Low-level map delete** | `DeleteService` (`*BPFLBMaps`) | `pkg/loadbalancer/maps/lbmaps.go` | 531 |

Removes entries from `cilium_lb4_services` / `cilium_lb6_services`.

---

## 7. Delete backends from eBPF maps

| Layer | Function (receiver) | File | Line |
|-------|---------------------|------|------|
| Reconciler delete | `deleteBackend` (`*BPFOps`) | `pkg/loadbalancer/reconciler/bpf_reconciler.go` | 1276 |
| **Low-level map delete** | `DeleteBackend` (`*BPFLBMaps`) | `pkg/loadbalancer/maps/lbmaps.go` | 501 |

Removes entries from `cilium_lb4_backends` / `cilium_lb6_backends`.

---

## Notes

- The load-balancer control-plane is **StateDB-driven**: desired Frontend/Backend state lives
  in StateDB tables, and `BPFOps` (implementing `reconciler.Operations`) reconciles it into BPF
  maps via the `LBMaps` interface (`*BPFLBMaps`).
- Legacy implementation (older releases) lived in `pkg/maps/lbmap` (`lbmap.go`) with
  `UpsertService` / `DeleteService` / `UpsertBackend` / `DeleteBackend`. The table above
  reflects the current `pkg/loadbalancer` code.
- Line numbers reflect the current checked-out tree and may drift with future commits;
  the function names/receivers are the stable reference.

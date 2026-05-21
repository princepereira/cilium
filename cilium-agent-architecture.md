# Cilium Agent Architecture — Complete Code Flow Guide

---

## Table of Contents

1. [Linux-Specific Code](#1-linux-specific-code)
2. [Cilium Agent Startup Flow](#2-cilium-agent-startup-flow)
3. [Hive/Cell Dependency Injection](#3-hivecell-dependency-injection)
4. [Daemon Initialization Phases](#4-daemon-initialization-phases)
5. [Kube-Proxy Replacement (KPR) Code Flow](#5-kube-proxy-replacement-kpr-code-flow)
6. [BPF Maps & Datapath](#6-bpf-maps--datapath)
7. [Key Files Reference](#7-key-files-reference)

---

## 1. Linux-Specific Code

### Main Directories

| Directory | Purpose |
|-----------|---------|
| `pkg/datapath/linux/` (115+ files) | Primary Linux networking: routing, IPsec, sysctl, bandwidth, netlink wrappers |
| `pkg/bpf/` (33 files, 8 `_linux.go`) | eBPF program/map lifecycle management |
| `pkg/datapath/loader/` | Compiles and loads BPF programs into kernel hooks (TC, XDP, TCX) |
| `pkg/datapath/iptables/` | Iptables/ipset integration |
| `pkg/maps/` (33 subdirs) | BPF map types (policy, conntrack, NAT, ipcache, metrics, etc.) |
| `pkg/netns/` | Linux network namespace handling |
| `pkg/cgroups/` | Cgroup v2 mounting and BPF attachment |
| `pkg/node/` | Node address/boot ID discovery via netlink |
| `pkg/mountinfo/` | Reads `/proc/*/mountinfo` |
| `bpf/` | C source for eBPF programs (`bpf_lxc.c`, `bpf_host.c`, `bpf_overlay.c`, etc.) |

### Categories of Linux-Specific Functionality

| Category | Primary Packages | Purpose |
|----------|------------------|---------|
| **eBPF Programs** | `pkg/bpf/`, `pkg/datapath/loader/`, `bpf/` | Kernel packet filtering, NAT, load balancing |
| **Network Namespaces** | `pkg/netns/`, `pkg/endpoint/` | Container network isolation |
| **Netlink** | `pkg/datapath/linux/safenetlink/`, `pkg/datapath/linux/route/` | Routing, link management, address config |
| **Iptables/Nftables** | `pkg/datapath/iptables/` | Packet filtering, port forwarding (legacy path) |
| **Routing** | `pkg/datapath/linux/route/reconciler/` | Linux routing table management |
| **IPsec** | `pkg/datapath/linux/ipsec/` | Encrypted tunneling |
| **Cgroups** | `pkg/cgroups/`, `pkg/testutils/` | Process grouping, BPF program attachment |
| **Sysctl** | `pkg/datapath/linux/sysctl/` | Kernel parameter tuning via `/proc/sys` |
| **XDP** | `pkg/datapath/xdp/`, `pkg/datapath/loader/xdp.go` | High-performance packet processing |
| **BPF Maps** | `pkg/maps/` (33 map types) | State storage for BPF programs |
| **System Integration** | `pkg/node/`, `pkg/mountinfo/` | Kernel feature detection, boot ID retrieval |

### Build Tag & Fallback Patterns

- **~156 `_linux.go` files** with `//go:build linux` build tags
- **~34 `_other.go` fallback stubs** for non-Linux (Darwin/Windows)
- **Layered syscall abstraction**:
  - Layer 1: `golang.org/x/sys/unix` — raw syscalls
  - Layer 2: `vishvananda/netlink`, `cilium/ebpf` — high-level abstractions
  - Layer 3: `pkg/datapath/linux/*`, `pkg/bpf/` — Cilium business logic

---

## 2. Cilium Agent Startup Flow

### Entry Point — `daemon/main.go`

```go
func main() {
    hiveFn := func() *hive.Hive {
        return hive.New(cmd.Agent)  // assembles all "cells" (modules)
    }
    cmd.Execute(cmd.NewAgentCmd(hiveFn))
}
```

A **Hive** is Cilium's dependency injection container. It's populated with **cells** (modules that provide/consume dependencies), then `h.Run()` starts everything.

### Command & Config — `daemon/cmd/root.go`

`NewAgentCmd()` creates a Cobra command that:
1. Registers ~300+ CLI flags via `InitGlobalFlags()`
2. Loads config from file/env/flags into `option.Config` (`pkg/option`)
3. Validates config via `option.Config.Validate()`
4. Calls `h.Run()` — starts the hive lifecycle

Configuration sources (in priority order):
1. CLI flags
2. Environment variables
3. Config file (`/etc/cilium/cilium.yaml`, `~/.ciliumd.yaml`, or `--config-file`)
4. Config directory (`--config-dir` — one file per option)

---

## 3. Hive/Cell Dependency Injection

### Cell Assembly — `daemon/cmd/cells.go`

The `Agent` cell module defines the full dependency tree, split into two groups:

#### Infrastructure Cells

| Cell | Purpose |
|------|---------|
| `k8sClient.Cell` | Kubernetes API client |
| `kvstore.Cell` | etcd/consul client |
| `server.Cell` | REST API on UNIX socket (`/var/run/cilium/cilium.sock`) |
| `metrics.AgentCell` | Prometheus metrics |
| `cni.Cell` | CNI plugin support |
| `pprof.Cell` | Profiling endpoints |
| `gops.Cell` | Go process diagnostics |
| `shell.ServerCell` | Shell access socket |

#### Control Plane Cells

| Cell | Purpose |
|------|---------|
| `datapath.Cell` | eBPF program loading & BPF map management |
| `policy.Cell` | Security policy engine |
| `endpoint.Cell` | Pod endpoint lifecycle |
| `identity.Cell` | Security identity allocation |
| `ipcache.Cell` | IP → identity mappings |
| `ipamcell.Cell` | IP address management |
| `loadbalancer_cell.Cell` | Service load balancing (kube-proxy replacement) |
| `watchers.Cell` | Kubernetes resource watchers |
| `nodediscovery.Cell` | Local/remote node discovery |
| `clustermesh.Cell` | Multi-cluster support |
| `hubble.Cell` | Flow monitoring |
| `health.Cell` | Connectivity probes |
| `bgp.Cell` | BGP control plane |
| `proxy.Cell` + `envoy.Cell` | L7 proxy |
| `restapi.Cell` | REST API handlers |
| `kpr.Cell` | Kube-proxy replacement |

### Hive Mechanism

- `cell.Provide()` — functions that provide dependencies
- `cell.Invoke()` — functions that consume dependencies & execute
- `cell.Lifecycle` — OnStart/OnStop hooks for initialization/cleanup
- `cell.Module()` — groups related cells

---

## 4. Daemon Initialization Phases

### Phase 1: `daemonConfigCell` (OnStart Hook)

Function: `daemonConfigInitialization()`

1. **Validate config** — checks mutual exclusivity (WireGuard vs IPSec, etc.)
2. **Initialize KPR options** — kube-proxy replacement settings
3. **Store config to disk** — `option.Config.StoreInFile()`
4. **Resolve DaemonConfig promise** — other cells await this
5. **Register background validation job** — checks config drift every 61 sec

### Phase 2: `daemonCell` (OnStart Hook)

Function: `daemonLegacyInitialization()` → `configureDaemon()`

Critical initialization order:

```
 1. Wait for K8s CRDs to sync
 2. Create CiliumNode CRD
 3. Detect devices (native, direct-routing) from StateDB
 4. Finish kube-proxy replacement init
 5. Start K8s watchers (pods, services, policies, nodes, identities)
 6. Configure & start IPAM
 7. Restore old endpoints (from previous agent run)
 8. Allocate infrastructure IPs (host, health, ingress endpoints)
 9. Start node discovery & annotate K8s node
10. Initialize identity allocator (connects to KV store)
11. Sync host IPs → BPF ipcache map
12. Start IPSec background jobs
13. Validate post-init state
```

### Runtime

After all cells start, each subsystem runs independently:

- **K8s watchers** react to resource changes (new pods, policy updates, service changes)
- **Policy engine** regenerates BPF policy maps when rules change
- **Endpoint manager** programs per-pod BPF programs and manages their lifecycle
- **Controllers** run periodic reconciliation (IPAM cleanup, config drift, health checks)
- **BPF datapath** handles packet processing in the kernel

State is shared across subsystems via **StateDB** (thread-safe tables with read/write transactions).

### Graceful Shutdown

On SIGTERM/SIGINT:
1. `cancelDaemonCtx()` — cancels daemon-wide context, all loops exit
2. `unloadDNSPolicies()` — cleans up DNS rules
3. All cell `OnStop` hooks execute in **reverse dependency order**
4. `pidfile.Clean()` → process exits

---

## 5. Kube-Proxy Replacement (KPR) Code Flow

### Overview

Cilium replaces kube-proxy by watching K8s Services/EndpointSlices and programming eBPF maps in the kernel to perform service load balancing entirely in the datapath.

### Data Flow Chain

```
K8s API Server
       │
       ▼
K8s Watcher Layer
       │  Watch Services, EndpointSlices, Pods
       ▼
K8s Reflector Layer  (pkg/loadbalancer/reflectors/)
       │  convertService(): K8s → Internal representation
       │  Generate Frontends: ClusterIP, NodePort, LoadBalancer, ExternalIP
       │  createBackends(): EndpointSlice → Backends
       ▼
StateDB Writer  (pkg/loadbalancer/writer/)
       │  Writer.UpsertServiceAndFrontends()
       │  Writer.UpsertBackend()
       ▼
StateDB Tables (in-memory)
       │  Services Table
       │  Frontends Table (Status: Pending → Done)
       │  Backends Table (State: Active/Quarantined/Terminating)
       ▼
BPF Reconciler  (pkg/loadbalancer/reconciler/)
       │  Watch Frontends with Status=Pending
       │  updateFrontend(): Allocate IDs, write BPF maps
       ▼
BPF Maps (kernel)
       │  cilium_lb4_services_v2, cilium_lb4_backends_v2
       │  cilium_lb4_reverse_nat, cilium_lb_affinity_match
       │  cilium_lb4_maglev, cilium_lb4_source_range
       ▼
BPF Datapath Programs
       bpf_sock.c, bpf_lxc.c, bpf_host.c, bpf_xdp.c
```

### Step 1: KPR Initialization (`pkg/kpr/initializer/`)

- `InitKubeProxyReplacementOptions()` — validates config (DSR mode, XDP acceleration, RSS CIDRs), sets LB flags at startup
- `FinishKubeProxyReplacementInit()` — finalizes native device selection after device detection

### Step 2: K8s Watching & Reflection (`pkg/loadbalancer/reflectors/`)

- Watchers stream Service + EndpointSlice events from the K8s API
- `runServiceEndpointsReflector()` buffers events in 500ms batches
- `convertService()` (`conversions.go`) translates K8s objects into internal representation:

```
K8s Service → Internal Service:
  - Name: namespace/name
  - ExtTrafficPolicy: Local/Cluster
  - IntTrafficPolicy: Local/Cluster
  - SessionAffinity: true/false + timeout
  - SourceRanges: loadBalancerSourceRanges CIDRs

Frontends generated:
  - ClusterIP frontends (ScopeExternal, ScopeInternal based on policies)
  - NodePort frontends (one per node address)
  - LoadBalancer frontends (for each LoadBalancerIP)
  - ExternalIP frontends
```

### Step 3: StateDB Write (`pkg/loadbalancer/writer/`)

- `Writer.UpsertServiceAndFrontends(txn, svc, fes...)` — creates/updates Service + Frontends
- `Writer.DeleteServiceAndFrontends(txn, name)` — removes service and its frontends
- `Writer.UpsertBackend(txn, backend)` — adds/updates backend (from EndpointSlice)
- Frontends are created with `Status=Pending` (awaiting BPF reconciliation)

### Step 4: BPF Reconciliation (`pkg/loadbalancer/reconciler/`)

The reconciler watches for `Pending` frontends, then `updateFrontend()` executes:

1. **Allocate ServiceID** — unique ID for this service
2. **Write Service map entries** — master slot (count, flags, affinity timeout) + per-backend slots (backend_id)
3. **Write Backend map entries** — BackendID → IP:port mapping
4. **Write RevNat entries** — for reverse translation (hairpin, reply packets)
5. **Write AffinityMatch** (if SessionAffinity) — client_ip → BackendID sticky mapping
6. **Write Maglev table** (if Maglev algorithm) — consistent hash: slot → BackendID
7. **Write SourceRange entries** (if LoadBalancerSourceRanges) — CIDR-based access control
8. **NodePort expansion** — creates frontends for each node address
9. **Mark Frontend Status=Done**

Periodic `Prune()` cleans orphaned map entries (service slots, backends, RevNat, Maglev, source ranges).

### Step 5: BPF Datapath

- `lb4_lookup_service()` in `bpf/lib/lb.h` — core lookup: matches packet dest against service map, selects backend
- `bpf/lib/nodeport.h` — handles NodePort/DSR/SNAT forwarding
- Called from 4 BPF hook points:

| BPF Program | Hook Point | Purpose |
|-------------|------------|---------|
| `bpf_sock.c` | Socket-level | Early binding at socket layer |
| `bpf_lxc.c` | Per-endpoint (TC) | Pod egress load balancing |
| `bpf_host.c` | Host (TC) | Host-originated traffic LB |
| `bpf_xdp.c` | XDP | High-performance fast-path |

---

## 6. BPF Maps & Datapath

### Service Maps (`cilium_lb4_services_v2` / `cilium_lb6_services_v2`)

```c
struct lb4_key {
    __be32 address;        // Service VIP
    __be16 dport;          // Destination port
    __u16  backend_slot;   // 0=master, 1..N=backends
    __u8   proto;          // IPPROTO_TCP, etc.
    __u8   scope;          // External (0) / Internal (1)
};

struct lb4_service {
    __u32 backend_id;          // Backend ID (slot > 0)
    __u32 affinity_timeout;    // Timeout (master slot)
    __u16 count;               // Number of backends (master)
    __u16 rev_nat_index;       // RevNat ID
    __u8  flags;               // SVC_FLAG_*
    __u16 qcount;              // Quarantined count
};
```

### Backend Maps (`cilium_lb4_backends_v2` / `cilium_lb6_backends_v2`)

```c
// Key: BackendID (u32)
struct lb4_backend {
    __be32 address;        // Backend IP
    __be16 port;           // Backend port
    __u8   proto;          // Protocol
    __u8   flags;          // Backend flags
    __u16  cluster_id;     // Cluster ID (multi-cluster)
    __u8   zone;           // Zone ID (topology-aware LB)
};
```

### Other Maps

| Map | Purpose |
|-----|---------|
| `cilium_lb4_reverse_nat` | RevNatID → original client address (reply translation) |
| `cilium_lb_affinity_match` | client_ip + ServiceID → BackendID (session affinity) |
| `cilium_lb4_maglev` | hash_slot → BackendID (consistent hashing) |
| `cilium_lb4_source_range` | CIDR + RevNatID (LoadBalancerSourceRanges enforcement) |

### Traffic Policy Scopes

- **ScopeExternal (0)**: North-South traffic (external → service)
- **ScopeInternal (1)**: East-West traffic (pod → service within cluster)

When `ExternalTrafficPolicy != InternalTrafficPolicy`, two separate service entries are created with different scopes and backend sets.

### Session Affinity Flow

1. BPF extracts client IP from packet source
2. Lookup AffinityMatch: `(ServiceID, hash(client_ip))` → BackendID
3. If found → use same backend (sticky)
4. If not found → select backend via algorithm, store new affinity entry
5. Entry expires after configured timeout

---

## 7. Key Files Reference

### Entry & Initialization

| File | Role |
|------|------|
| `daemon/main.go` | Entry point |
| `daemon/cmd/root.go` | Cobra command, flag registration |
| `daemon/cmd/cells.go` | Cell hierarchy (full module tree) |
| `daemon/cmd/daemon_main.go` | Config init + lifecycle hooks |
| `daemon/cmd/daemon.go` | `configureDaemon()` — ordered subsystem init |
| `pkg/option/config.go` | `DaemonConfig` struct (all config options) |
| `pkg/hive/` | Hive dependency injection framework |

### Kube-Proxy Replacement

| File | Role |
|------|------|
| `pkg/kpr/initializer/cell.go` | KPR module definition |
| `pkg/kpr/initializer/kube_proxy_replacement.go` | KPR initialization logic |
| `pkg/loadbalancer/reflectors/k8s.go` | K8s → internal conversion reflector |
| `pkg/loadbalancer/reflectors/conversions.go` | Service conversion logic |
| `pkg/loadbalancer/writer/writer.go` | StateDB write access |
| `pkg/loadbalancer/service.go` | Service struct |
| `pkg/loadbalancer/frontend.go` | Frontend struct |
| `pkg/loadbalancer/backend.go` | Backend struct |
| `pkg/loadbalancer/reconciler/bpf_reconciler.go` | BPF map reconciler |
| `pkg/loadbalancer/reconciler/cell.go` | Reconciler cell definition |
| `pkg/loadbalancer/maps/lbmaps.go` | BPF map interface |
| `pkg/loadbalancer/maps/types.go` | BPF map key/value types |

### BPF Datapath

| File | Role |
|------|------|
| `bpf/lib/lb.h` | Core load balancing functions |
| `bpf/lib/nodeport.h` | NodePort/DSR/SNAT handling |
| `bpf/bpf_sock.c` | Socket-level LB |
| `bpf/bpf_lxc.c` | Per-endpoint LB |
| `bpf/bpf_host.c` | Host-level LB |
| `bpf/bpf_xdp.c` | XDP fast-path |

### Linux-Specific Packages

| File | Role |
|------|------|
| `pkg/datapath/linux/` | Linux networking implementation |
| `pkg/datapath/linux/safenetlink/` | Safe netlink wrapper (retries, error handling) |
| `pkg/datapath/linux/route/reconciler/` | Route table management |
| `pkg/datapath/linux/ipsec/` | IPsec encryption |
| `pkg/datapath/linux/sysctl/` | Kernel parameter tuning |
| `pkg/datapath/iptables/` | Iptables integration |
| `pkg/datapath/loader/` | BPF program compilation & loading |
| `pkg/bpf/` | eBPF lifecycle management |
| `pkg/netns/` | Network namespace handling |
| `pkg/cgroups/` | Cgroup management |
| `pkg/node/` | Node/host configuration |

### Key Data Structures

| Struct | Package | Purpose |
|--------|---------|---------|
| `DaemonConfig` | `pkg/option` | Global daemon configuration |
| `Hive` | `pkg/hive` | Dependency injection container |
| `cell.Lifecycle` | `github.com/cilium/hive/cell` | OnStart/OnStop hooks |
| `EndpointManager` | `pkg/endpointmanager` | Manages pod endpoints |
| `PolicyRepository` | `pkg/policy` | Stores security policies |
| `IdentityAllocator` | `pkg/identity` | Allocates security identities |
| `K8sWatcher` | `pkg/k8s/watchers` | Watches K8s resources |
| `Datapath` | `pkg/datapath` | BPF/datapath abstraction |
| `StateDB` | `github.com/cilium/statedb` | Thread-safe state tables |

---

*Generated from Cilium source code analysis — May 2026*

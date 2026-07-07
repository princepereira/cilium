# Cilium-Agent Windows Port — Minimal Feature Plan

Goal: bring up a minimal Windows cilium-agent on the **CNC datapath** (not eBPF), starting
with two features only: **load-balancer** (Phase 1) and **endpoint manager** (Phase 2).

## Confirmed decisions

1. **Endpoint creation path** = CNI plugin + agent REST API (same shape as Linux;
   `PutEndpointID` / `DeleteEndpointID`).
2. **Node addresses on Windows** = sourced from `node.LocalNodeStore` initially (a Windows
   `NodeAddress` provider), backed by CNC later. This replaces the Linux netlink
   `DevicesController` that populates `Table[tables.NodeAddress]`.
3. **Scaffold** the build-tagged agent composition now (done — see "Files changed").

## Assembly

```
cilium-agent(windows) = MinimalInfra + ControlPlane(min) + Datapath(CNC)
```

StateDB + jobs come from the base Hive (`pkg/hive`), so they are not listed. A slim
Infrastructure is still mandatory (K8s client, REST API server, metrics, config).

### Proposed minimal cell tree

```
Agent(windows)                         daemon/cmd/cells_windows.go
├── MinimalInfra
│   ├── (base) statedb.Cell, job.Cell            [free from pkg/hive]
│   ├── k8sClient.Cell
│   ├── server.Cell (+ SpecCell)                 [endpoint REST API]
│   ├── metrics.AgentCell
│   └── daemonConfigCell / cni.Cell
├── ControlPlane(min)
│   ├── node.LocalNodeStoreCell
│   ├── maglev.Cell                              [portable]
│   ├── kpr.Cell                                 [config]
│   ├── identity.Cell, ipcache.Cell, ipam        [Phase 2 deps]
│   ├── policy.Cell, compute.Cell                [Phase 2 deps]
│   ├── loadbalancer_cell.Cell                   [Phase 1; redirectpolicy OFF]
│   └── endpoint.Cell                            [Phase 2]
└── Datapath(CNC)
    ├── loadbalancer/maps → CNCLBMaps            [DONE]
    ├── nodeaddress(windows)                     [NEW — Phase 1]
    ├── endpointloader(windows) → CNC            [NEW — Phase 2]
    └── connector(windows) → HNS/HCN             [NEW — Phase 2]
```

## Dependency surface (verified)

### Load-balancer — `pkg/loadbalancer/cell`
Sub-cells: config + `writer` + `reflectors` + `maps` + `reconciler` + `redirectpolicy` +
`healthserver`. The reconciler ([bpf_reconciler.go#L179](pkg/loadbalancer/reconciler/bpf_reconciler.go#L179)) needs:

| Dep | Source | Windows status |
|---|---|---|
| `maps.LBMaps` | `loadbalancer/maps` | ✅ `CNCLBMaps` done |
| `Table[tables.NodeAddress]` | datapath `tables.NodeAddressCell` ← DevicesController (netlink) | ❌ Windows NodeAddress source |
| `*maglev.Maglev` | `maglev.Cell` | ✅ portable |
| `Config`/`ExternalConfig`, `kpr`, `LocalNodeStore` | config cells | ✅ portable |
| `redirectpolicy` sub-cell | needs endpointmanager + skip-LB map | ⚠️ disable on Windows in Phase 1 |

### Endpoint manager — `pkg/endpoint/cell`
Sub-cells: `endpointmanager` + `endpointcreator` + `endpointmetadata` + `endpointapi` +
`endpointcleanup` + `RegeneratorCell` + `watchdog`. Regeneration needs:

| Dep | Purpose | Windows status |
|---|---|---|
| `loader` | compile/load eBPF | ❌ CNC endpoint programming |
| `connector` | veth/netkit + `LinkSetNsFd` | ❌ HNS/HCN endpoint |
| `identity`, `ipcache`, `policy`/`compute` | identity + policy | ✅ mostly portable (BPF sync = datapath) |
| `ipam`, `proxy` | IP alloc / L7 redirect | ✅ IPAM portable / ⚠️ proxy Linux (drop) |

## Phasing

**Phase 1 — Load-balancer only** (clean reflect→reconcile→CNC path).
Blockers: (a) Windows `NodeAddress` source cell; (b) disable `redirectpolicy` on Windows.
Then wire `loadbalancer_cell.Cell` in `cells_windows.go`.

**Phase 2 — Endpoint manager.**
Needs CNC `loader` + HNS `connector`; keep identity/policy/ipcache control logic, stub BPF sync.

## Work items

1. **Windows `NodeAddress` source** — provide `Table[tables.NodeAddress]` from
   `LocalNodeStore` (Phase 1 unblocker).
2. **Disable `redirectpolicy.Cell` on Windows** — build-tag it out or gate by config.
3. Wire `loadbalancer_cell.Cell` (+ its portable deps) into `cells_windows.go`.
4. Phase 2: CNC `loader` + HNS `connector` cells; then wire `endpoint.Cell`.

## Files changed (this step)

- **`daemon/main.go`** → `//go:build linux` (imports the Linux-only `daemon/cmd`, so excluded on Windows).
- **`daemon/main_windows.go`** (`//go:build windows`, package `main`) — the **live minimal Windows
  agent entrypoint**. Boots the Hive (StateDB + jobs from `pkg/hive`) and wires the currently
  Windows-compilable cells: `maglev.Cell`, `loadbalancer.ConfigCell`, `writer.Cell` (LB StateDB
  tables + Writer). **`go build ./daemon/` succeeds for both GOOS=windows and GOOS=linux.**
- Fixed pre-existing split bug: moved `"os"` import from `lbmaps.go` (untagged) to
  `lbmaps_linux.go` — Linux build of `pkg/loadbalancer/maps` + `daemon/cmd` is green again.

> Note: `daemon/cmd/cells.go` is **untagged/unchanged**. An earlier attempt split it into
> `cells_linux.go` + `cells_windows.go` (to put the Windows `Agent` inside package `cmd`), but that
> was reverted: package `daemon/cmd` cannot build on Windows (Linux-only siblings), so the Windows
> composition lives in `daemon/main_windows.go` (package `main`) instead. Only the
> `main.go`/`main_windows.go` split is needed.

## Windows compile frontier (empirically probed, GOOS=windows)

**Compiles today:** `pkg/hive`, `pkg/option`, `pkg/metrics`, `pkg/k8s`, `pkg/k8s/client`,
`pkg/maglev`, `pkg/node`, `pkg/kpr`, `pkg/datapath/tables` (incl. NodeAddress), `pkg/loadbalancer`,
`pkg/loadbalancer/writer`.

**Does NOT compile:** `pkg/loadbalancer/maps` (→ `pkg/datapath/maps`/`linux/probes`/`xdp` — eBPF
`unix.BPF_*`, `link.*`, `netlink.*`), `pkg/loadbalancer/reflectors`, `pkg/loadbalancer/reconciler`,
`pkg/loadbalancer/cell`, `pkg/node/manager`, `pkg/statedb` (cilium wrapper).

**Key unlock for Phase 1:** port `pkg/loadbalancer/maps` so its untagged surface no longer imports
`pkg/datapath/maps`/`probes`/`xdp` (move those into `*_linux.go`; the Windows path uses `CNCLBMaps`).
That unblocks `reconciler` → `loadbalancer/cell`, then swap `writer.Cell` for the full
`loadbalancer_cell.Cell` in `daemon/main_windows.go`.

## Notes / caveats

- The whole `daemon/cmd` package won't fully compile on Windows yet — many untagged files
  (`daemon_main.go`, `daemon.go`, …) are Linux-oriented. The `cells_windows.go` skeleton is a
  build-tagged blueprint to grow incrementally, not a full Windows build.
- Keep the cncshim `// indirect` caveat in mind: `go mod tidy` under GOOS=linux drops it.

# Running the Cilium Agent on Windows Nodes

This guide describes how to build and run `cilium-agent.exe` on a Windows
Kubernetes node backed by [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows).

It is the result of the Windows port effort (Stages 1-5): Linux-only startup
paths have Windows/no-op counterparts behind build tags, and BPF map specs are
translated to the native Windows platform at map-creation time.

> **Scope / status:** The agent currently starts through datapath
> initialization, connects to the API server, creates its `CiliumNode`
> resource, and then waits on IPAM (PodCIDR allocation by the cilium-operator).
> Full pod networking is still being brought up. Treat this as a
> developer/bring-up workflow, not a production deployment guide.

---

## Prerequisites

- A Windows node (Windows Server 2022 or later recommended) joined to a
  Kubernetes cluster, with the Windows kubelet configured.
- [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows) installed on
  the node so that `ebpfapi.dll` (the efw user-mode API) is present and the
  eBPF execution context / drivers are running.
- Go 1.26+ on the build machine (cross-compiling from Linux/macOS/Windows all
  work; the commands below use Windows PowerShell).
- Cluster access via a kubeconfig, plus the Cilium CRDs installed
  (`kubectl get crd | Select-String cilium`).
- The cilium-operator running in the cluster (it allocates the PodCIDR for the
  Windows `CiliumNode` in cluster-pool IPAM).

---

## Cluster-side setup (RBAC + kubeconfig)

Before the Windows node can run the agent, the cluster must have a
`ServiceAccount`, the Cilium CRDs, RBAC (`ClusterRole` + `ClusterRoleBinding`),
a long-lived SA token, and a kubeconfig built from that token. Run these on a
machine with cluster-admin `kubectl` access (Part A). Parts B and C run on the
Windows node.

### Part A - Prepare the ServiceAccount, RBAC, and kubeconfig

#### 1. ServiceAccount

The `kube-system` namespace already exists, so only the `ServiceAccount` is
needed (this is idempotent enough; an `AlreadyExists` error is harmless):

```bash
kubectl -n kube-system create serviceaccount cilium
```

#### 2. Install the Cilium CRDs

The agent does `list`/`watch` on `cilium.io` resources; without the CRDs it
fails to start.

```bash
# From the repo Helm chart, or upstream:
helm template cilium ./install/kubernetes/cilium \
  --namespace kube-system \
  --set preflight.enabled=false \
  --show-only templates/cilium-agent/clusterrole.yaml > cilium-clusterrole.yaml
# CRDs are created by the operator on first run, or apply
# pkg/k8s/apis/.../crds directly.
```

#### 3. ClusterRole + ClusterRoleBinding

Grounded in `install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml`.

Save the following as `cilium-clusterrole.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cilium
rules:
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get","list","watch"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get","list","watch"]
- apiGroups: [""]
  resources: ["namespaces","services","pods","nodes","secrets","configmaps"]
  verbs: ["get","list","watch"]
- apiGroups: [""]
  resources: ["nodes/status"]
  verbs: ["patch"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["get","list","watch"]
- apiGroups: ["cilium.io"]
  resources:
  - ciliumloadbalancerippools
  - ciliumclusterwidenetworkpolicies
  - ciliumendpoints
  - ciliumendpointslices
  - ciliumidentities
  - ciliumlocalredirectpolicies
  - ciliumnetworkpolicies
  - ciliumnodes
  - ciliumnodeconfigs
  - ciliumcidrgroups
  - ciliumpodippools
  verbs: ["list","watch"]
- apiGroups: ["cilium.io"]
  resources: ["ciliumidentities","ciliumendpoints","ciliumnodes"]
  verbs: ["create"]
- apiGroups: ["cilium.io"]
  resources: ["ciliumidentities"]
  verbs: ["update"]
- apiGroups: ["cilium.io"]
  resources: ["ciliumendpoints"]
  verbs: ["delete","get"]
- apiGroups: ["cilium.io"]
  resources: ["ciliumnodes","ciliumnodes/status"]
  verbs: ["get","update"]
- apiGroups: ["cilium.io"]
  resources: ["ciliumendpoints/status","ciliumendpoints"]
  verbs: ["patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cilium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cilium
subjects:
- kind: ServiceAccount
  name: cilium
  namespace: kube-system
```

Then apply it (works from both PowerShell and bash):

```bash
kubectl apply -f cilium-clusterrole.yaml
```

> If you update this ClusterRole later (for example to add `configmaps`),
> re-run `kubectl apply -f cilium-clusterrole.yaml` to push the change. The
> agent's informers pick up the new permissions on their next retry (no
> restart required).

#### 4. Create a long-lived ServiceAccount token

Kubernetes >= 1.24 (and AKS) does not auto-create a token Secret, so create one
explicitly. Save the following as `cilium-token.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cilium-token
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: cilium
type: kubernetes.io/service-account-token
```

Then apply it:

```bash
kubectl apply -f cilium-token.yaml
```

#### 5. Build the kubeconfig for the Windows node

PowerShell (recommended if you are on Windows - avoids bash heredocs):

```powershell
$APISERVER = kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'
$CA        = kubectl -n kube-system get secret cilium-token -o jsonpath='{.data.ca\.crt}'
$TOKEN     = [System.Text.Encoding]::UTF8.GetString(
               [System.Convert]::FromBase64String(
                 (kubectl -n kube-system get secret cilium-token -o jsonpath='{.data.token}')))

@"
apiVersion: v1
kind: Config
clusters:
- name: aks
  cluster:
    server: $APISERVER
    certificate-authority-data: $CA
contexts:
- name: cilium
  context:
    cluster: aks
    user: cilium
current-context: cilium
users:
- name: cilium
  user:
    token: $TOKEN
"@ | Set-Content -NoNewline -Encoding ascii cilium-kubeconfig.yaml
```

bash (Linux/macOS admin machine):

```bash
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl -n kube-system get secret cilium-token -o jsonpath='{.data.ca\.crt}')
TOKEN=$(kubectl -n kube-system get secret cilium-token -o jsonpath='{.data.token}' | base64 -d)

cat > cilium-kubeconfig.yaml <<EOF
apiVersion: v1
kind: Config
clusters:
- name: aks
  cluster:
    server: ${APISERVER}
    certificate-authority-data: ${CA}
contexts:
- name: cilium
  context:
    cluster: aks
    user: cilium
current-context: cilium
users:
- name: cilium
  user:
    token: ${TOKEN}
EOF
```

> **Note:** The AKS API server is publicly reachable (or via the node's VNet for
> private clusters). Ensure the Windows node can reach the API server on port
> 443 (the `server:` URL above).

### Part B - Copy the kubeconfig to the Windows node

```powershell
New-Item -ItemType Directory -Force C:\cilium\etc, C:\cilium\state | Out-Null
# scp / Copy-Item the file to:
#   C:\cilium\etc\cilium-kubeconfig.yaml
```

### Part C - Start cilium-agent on the Windows node

Prereq on the node: eBPF-for-Windows installed (provides `ebpfapi.dll` and the
`/ebpf/global` pin namespace).

```powershell
New-Item -ItemType Directory -Force C:\cilium\state | Out-Null

.\cilium-agent.exe `
  --k8s-kubeconfig-path C:\cilium\etc\cilium-kubeconfig.yaml `
  --state-dir C:\cilium\state `
  --socket-path C:\cilium\state\cilium.sock `
  --k8s-namespace kube-system `
  --enable-ipv6=false `
  --enable-l7-proxy=false
```

Notes on the flags (why these, given the port):

- **No `--bpf-root`** - the Windows pin root is hard-coded to `/ebpf/global/` in
  winebpfmap; the flag is ignored.
- **No `--cgroup-root`** - cgroup/socket-LB attach is a Windows no-op stub, so
  leaving it default is harmless (socket-termination degrades cleanly).
- **`--k8s-kubeconfig-path`** - the SA-token kubeconfig from Part A; this grants
  the agent kube-apiserver access.
- **`--enable-ipv6=false`, `--enable-l7-proxy=false`** - reduce Linux-only
  surface for a first bring-up.
- **`--enable-k8s`** defaults to `true`, so the k8s clientset is on
  automatically.

Verify connectivity once it is up (in another shell on the node):

```powershell
kubectl --kubeconfig C:\cilium\etc\cilium-kubeconfig.yaml auth can-i list ciliumnodes
# should print: yes
```

---

## Step 1 - Build `cilium-agent.exe`

From the repository root, cross-compile the agent for Windows:

```powershell
$env:GOOS   = "windows"
$env:GOARCH = "amd64"
go build -o bin\cilium-agent.exe .\daemon
```

The build is expected to be green on both platforms. Optionally verify Linux is
unaffected:

```powershell
$env:GOOS = "linux"
go build ./...
```

Copy `bin\cilium-agent.exe` to the Windows node (e.g. `C:\cilium\cilium-agent.exe`).

## Step 2 - Install / verify eBPF-for-Windows on the node

On the Windows node, confirm eBPF-for-Windows is installed and its service is
running so that map creation via `ebpfapi.dll` succeeds:

```powershell
# The efw user-mode API the agent binds to:
Test-Path "$env:SystemRoot\System32\ebpfapi.dll"

# eBPF-for-Windows service(s) should be present/running:
Get-Service | Where-Object { $_.Name -match 'ebpf|eBPFCore|NetEbpfExt' }
```

If these are missing, install eBPF-for-Windows first - the agent cannot create
BPF maps without it.

## Step 3 - Prepare the runtime directories

The agent expects a state/run directory tree on the node. Create the Cilium
state directory (the BPF template/`install-bpf` step is skipped on Windows):

```powershell
New-Item -ItemType Directory -Force -Path C:\cilium\state\state | Out-Null
```

> On Windows, the Linux-only `install-bpf` template check is a no-op, so you do
> **not** need `/var/lib/cilium/bpf`. The agent uses a Windows state directory
> (e.g. `C:\cilium\state`).

## Step 4 - Provide the kubeconfig and node identity

Make the cluster reachable and tell the agent which node it is running on. The
node name **must** match the Kubernetes/Windows node object name (required to
resolve the PodCIDR):

```powershell
$env:KUBECONFIG = "C:\cilium\kubeconfig"
$env:K8S_NODE_NAME = "aksnpwin000000"   # must match `kubectl get nodes`
```

## Step 5 - Ensure IPAM assigns a PodCIDR (cluster side)

**This is a hard gate.** On start, for cluster-pool IPAM the daemon calls
`WaitForNodeInformation` and **blocks indefinitely** until the node's
`CiliumNode` resource has an IPv4 PodCIDR
(`Waiting for k8s node information ... required IPv4 PodCIDR not available`).
The k8s Service/EndpointSlice watchers and **all datapath/eBPF map programming
run only after this wait returns** - so until a PodCIDR is assigned, new pods
and services will not appear in the logs and the eBPF maps will not be updated.

`ParseCiliumNode` populates the node's `IPv4AllocCIDR` from
`spec.ipam.podCIDRs` (or `spec.ipam.pools.allocated`). Check whether it is set:

```powershell
kubectl get ciliumnode $env:K8S_NODE_NAME -o yaml   # look for spec.ipam.podCIDRs
```

### Option A - Manually assign a PodCIDR (fastest for bring-up)

Pick a CIDR that does **not** overlap any other node's pod CIDR, and patch the
`CiliumNode`. Use the node name from `kubectl get nodes` (e.g.
`aksnpwin000000`).

bash:

```bash
kubectl patch ciliumnode aksnpwin000000 --type merge \
  -p '{"spec":{"ipam":{"podCIDRs":["10.244.1.0/24"]}}}'
```

PowerShell (the single-quote form above does **not** work - Windows strips the
inner double quotes, giving `invalid character 's' looking for beginning of
object key string`). Either escape the inner quotes:

```powershell
kubectl patch ciliumnode aksnpwin000000 --type merge -p '{\"spec\":{\"ipam\":{\"podCIDRs\":[\"10.244.1.0/24\"]}}}'
```

or, more robustly, use a patch file:

```powershell
'{"spec":{"ipam":{"podCIDRs":["10.244.1.0/24"]}}}' | Set-Content -NoNewline patch.json
kubectl patch ciliumnode aksnpwin000000 --type merge --patch-file patch.json
```

The agent's `CiliumNode` watch picks up the upsert, `waitForCIDR()` passes, and
the daemon proceeds to start the k8s watchers and program the maps.

> **Note:** If a cilium-operator is running with cluster-pool IPAM, it owns
> `spec.ipam.podCIDRs` and may overwrite a manual value. In that case use
> Option B instead.

### Option B - Let cilium-operator allocate it

The operator is what normally writes `spec.ipam.podCIDRs`. Ensure it is running
and configured with a pool:

```powershell
# Operator healthy?
kubectl -n kube-system get pods -l name=cilium-operator
# operator needs: --cluster-pool-ipv4-cidr / --cluster-pool-ipv4-mask-size
```

## Step 6 - Run the agent

Start the agent from an elevated (Administrator) PowerShell. Point the state and
run directories at Windows paths and disable Linux-only features that have no
Windows datapath yet:

```powershell
C:\cilium\cilium-agent.exe `
  --k8s-kubeconfig-path C:\cilium\kubeconfig `
  --state-dir C:\cilium\state `
  --run-dir C:\cilium\state `
  --ipam cluster-pool `
  --enable-ipv4 `
  --enable-ipv6=false `
  --enable-bpf-clock-probe=false `
  --enable-l7-proxy=false
```

Adjust flags to match your cluster (for example `--cluster-pool-*` on the
operator side, tunnel/native-routing mode, etc.).

## Step 7 - Verify it is up

A successful bring-up shows (approximately) this sequence in the log, with **no
`level=fatal`**:

```
Connected to apiserver
All Cilium CRDs have been found and are available
No eventsmap: monitor works only for agent events.
Datapath signal listener running
Successfully created CiliumNode resource
Waiting for k8s node information ... required IPv4 PodCIDR not available  # until IPAM assigns a PodCIDR
```

Once a PodCIDR is assigned (Step 5, Option A or B), the "Waiting for k8s node
information" warning clears and the agent continues: it starts the k8s
Service/EndpointSlice watchers and begins programming the eBPF maps.

---

## Expected non-fatal log noise on Windows

These are expected and are **not** failures:

- `Failed to mount cgroupv2 ... not implemented` - no cgroup v2 on Windows.
- `iptables ... executable file not found in %PATH%` - no iptables on Windows.
- `Auto-disabling "enable-bpf-clock-probe" ... /proc/schedstat` - no procfs.
- `check program 32: program cil_sock4_conne has zero memlock` - memlock stats
  are Linux-specific.
- `No eventsmap: monitor works only for agent events.` - the perf-event-array
  events map is not created on Windows (no `PerfEventArray` support in efw); the
  monitor degrades to agent-generated events only.

## What is different on Windows (design notes)

- **Map-type translation.** Cilium map specs use Linux-tagged `ebpf.MapType`
  constants. On Windows these are translated at both map-creation choke points
  (`pkg/bpf` `createMap` and `pkg/ebpf` `OpenOrCreate`) to the distinct
  Windows-tagged constants understood by eBPF-for-Windows (e.g. `LPMTrie ->
  WindowsLPMTrie`, `PerCPUHash -> WindowsPerCPUHash`). Linux `BPF_F_*` map
  flags (`NO_PREALLOC`, `RDONLY_PROG`) are dropped because efw rejects them.
- **Unsupported map types are no-op'd at the cell level.** `PerfEventArray`
  (events map, signal map) has no Windows equivalent, so those cells provide a
  nil/no-op map and dependent components degrade gracefully.
- **The datapath loader is a no-op on Windows.** `ReinitializeHostDev` /
  `Reinitialize` return success without loading Linux BPF programs; host
  datapath programs on Windows are managed by eBPF-for-Windows, not this loader.
- **Linux-only subsystems are stubbed** behind `*_windows.go` / `*_other.go`
  build tags (bandwidth manager, infra IP allocator, device tables, privileged
  checks, etc.) so the hive dependency graph resolves identically across
  platforms.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `map type X (linux): not supported on windows` | A map type without a Windows translation/equivalent | Add it to the translation table (`pkg/bpf/maptype_windows.go`) if efw supports it, or no-op the owning cell if it does not |
| `map create: flags: not supported on windows` | Non-zero Linux map flags reached efw | Flags are dropped in `ToPlatformMapFlags`; ensure the create path routes through `pkg/bpf`/`pkg/ebpf` |
| `datapath loader is not supported on this platform` | A loader entry point still returns the unsupported error | No-op the specific method in `pkg/datapath/loader/loader_other.go` |
| Stuck at `required IPv4 PodCIDR not available` | Operator has not allocated a PodCIDR | Check cilium-operator health and cluster-pool CIDR config; inspect `kubectl get ciliumnode <node> -o yaml` |
| `ebpfapi.dll` load failure / map creation panics | eBPF-for-Windows not installed or service stopped | Install/repair eBPF-for-Windows and verify its service is running |

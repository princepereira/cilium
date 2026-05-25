# Building Cilium Agent for Windows

The cilium-agent can be compiled for Windows nodes. On Windows, Linux eBPF map operations are replaced by [cncshim](https://github.com/princepereira/cncshim) API calls.

## Prerequisites

- Go 1.22+
- [cncshim](https://github.com/princepereira/cncshim/releases/tag/v0.1.0) running on the target Windows node
- Access to a Kubernetes cluster (kubeconfig or in-cluster ServiceAccount)

## RBAC Setup

The cilium-agent needs cluster-wide read access to watch Services and EndpointSlices. Apply the RBAC manifest from a machine with cluster-admin access:

```bash
kubectl apply -f install/windows/rbac.yaml
```

This creates a `cilium-agent-win` ServiceAccount, ClusterRole, and ClusterRoleBinding in `kube-system`.

**If running as a pod**, use `serviceAccountName: cilium-agent-win` in namespace `kube-system`.

**If running outside a pod** (e.g., directly on a Windows node with kubeconfig), bind the ClusterRole to your ServiceAccount:

```bash
# Replace <namespace> and <service-account> with your actual values
kubectl create clusterrolebinding cilium-agent-win-binding \
  --clusterrole=cilium-agent-win \
  --serviceaccount=<namespace>:<service-account>
```

For example, if the agent uses `demo:default`:

```bash
kubectl create clusterrolebinding cilium-agent-win-binding \
  --clusterrole=cilium-agent-win \
  --serviceaccount=demo:default
```

## Kubeconfig

The agent looks for Kubernetes API access in this order:

1. **In-cluster config** — auto-detected when running as a pod with a mounted ServiceAccount token
2. **KUBECONFIG env var** — set explicitly via `$env:KUBECONFIG = "C:\path\to\config"`
3. **Default path** — `%USERPROFILE%\.kube\config`

Common kubeconfig locations on Windows nodes:
- `C:\Users\<username>\.kube\config`
- `C:\k\config` (AKS / common K8s installers)

## Build Instructions

### Cross-compile from Linux/macOS

```bash
GOOS=windows GOARCH=amd64 go build -mod=vendor -o cilium-agent.exe ./daemon/
```

### Build on Windows (PowerShell)

```powershell
go build -mod=vendor -o cilium-agent.exe ./daemon/
```

### Linux build (default)

```bash
GOOS=linux GOARCH=amd64 go build -mod=vendor -o cilium-agent ./daemon/
```

## Architecture

On Windows, the following eBPF map operations are handled via cncshim:

| Component | cncshim API |
|-----------|-------------|
| IPCache | `SetIdentity` / `DeleteIdentity` |
| Load Balancer | `CreateLoadBalancerService` / `CreateLoadBalancerBackends` |
| Policy | `AddOrUpdateEndpointPolicies` / `DeleteEndpointPolicies` |
| Neighbors | `AddOrUpdateNeighbor` / `DeleteNeighbor` |
| Conntrack | `SetCtConfiguration` / `GetCtConfiguration` |
| SNAT | `AddSnatExcludedSubnets` / `DeleteSnatExcludedSubnets` |

## Running

Ensure [cncshim](https://github.com/princepereira/cncshim/releases/tag/v0.1.0) is running on the Windows node before starting the agent:

```powershell
# Start cncshim first (required)
.\cncshim.exe

# In another terminal, start cilium-agent
.\cilium-agent.exe
```

On startup the agent will:
1. Initialize the CNCShim client (connects to the local cncshim gRPC server)
2. Log `CNC API client initialized` with shim/API versions
3. Wait for shutdown signal (Ctrl+C or SIGTERM)

To stop the agent gracefully, press `Ctrl+C`.

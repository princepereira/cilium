# Building Cilium Agent for Windows

The cilium-agent can be compiled for Windows nodes. On Windows, Linux eBPF map operations are replaced by [cncshim](https://github.com/princepereira/cncshim) API calls.

## Prerequisites

- Go 1.22+
- [cncshim](https://github.com/princepereira/cncshim/releases/tag/v0.1.0) running on the target Windows node

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

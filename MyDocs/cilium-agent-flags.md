# cilium-agent.exe — startup flags explained

Command reference for running the agent on a Windows node:

```
cilium-agent.exe `
  --k8s-kubeconfig-path C:\cilium\etc\cilium-kubeconfig.yaml `
  --state-dir C:\cilium\state `
  --socket-path C:\cilium\state\cilium.sock `
  --k8s-namespace kube-system `
  --enable-ipv6=false `
  --enable-l7-proxy=false
```

| Flag | Value (example) | Default | Defined in |
|------|-----------------|---------|------------|
| `--k8s-kubeconfig-path` | `C:\cilium\etc\cilium-kubeconfig.yaml` | *(in-cluster)* | `pkg/k8s/client/config.go:78` |
| `--state-dir` | `C:\cilium\state` | `/var/run/cilium` | `daemon/cmd/daemon_main.go:534` |
| `--socket-path` | `C:\cilium\state\cilium.sock` | `/var/run/cilium/cilium.sock` | `daemon/cmd/daemon_main.go:531` |
| `--k8s-namespace` | `kube-system` | `""` | `daemon/cmd/daemon_main.go:377` |
| `--enable-ipv6` | `false` | see `defaults` | `daemon/cmd/daemon_main.go:208` |
| `--enable-l7-proxy` | `false` | see `defaults` | `daemon/cmd/daemon_main.go:295` |

## Details

### `--k8s-kubeconfig-path C:\cilium\etc\cilium-kubeconfig.yaml`
Absolute path of the Kubernetes kubeconfig file. This is how the agent
authenticates and talks to the Kubernetes API server — it reads Services,
EndpointSlices, Pods, CiliumEndpoints, etc. Without it the agent falls back to
in-cluster config (service-account token), which isn't available for a process
running directly on a Windows node outside a pod, so it is supplied explicitly.

### `--state-dir C:\cilium\state`
Directory to store runtime state (default on Linux is `/var/run/cilium`). The
agent persists per-node runtime data here — the `globals/` subfolder
(`StateDir/globals`), IPAM state, endpoint state, generated headers, etc. On
Windows it is redirected to a real Windows path.

### `--socket-path C:\cilium\state\cilium.sock`
Path of the daemon's API socket that it listens on for connections (default
`/var/run/cilium/cilium.sock`). This is the control socket the CLI
(`cilium status`, `cilium service list`, ...) and health tooling use to call the
agent's REST API. Here it is placed under the same state dir.

### `--k8s-namespace kube-system`
Name of the Kubernetes namespace in which Cilium is deployed. Used to scope
certain namespaced lookups / leader-election / CRD and pod self-identification
to the namespace where Cilium's own resources live.

### `--enable-ipv6=false`
Enables/disables IPv6 support. Setting `false` makes the agent run IPv4-only —
it won't allocate IPv6 addresses or program the IPv6 datapath / LB maps
(`cilium_lb6_*`). Matches Windows testing where only IPv4 services are exercised.

### `--enable-l7-proxy=false`
Enables the L7 proxy used for L7 policy enforcement and L7 visibility. Disabling
it turns off the Envoy-based L7 proxy path — appropriate on Windows since that
datapath/proxy isn't ported, and only L3/L4 load-balancing is needed.

## Note on `=` syntax for booleans

The two boolean flags use `--flag=false` because pflag booleans must use `=` to
pass an explicit `false`. A bare `--enable-ipv6 false` would treat `false` as a
positional argument and leave the flag at its default (`true`). String flags
(`--state-dir`, `--socket-path`, ...) accept a space-separated value normally.

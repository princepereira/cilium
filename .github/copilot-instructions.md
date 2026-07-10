# Copilot Instructions — Cilium (Windows Datapath Port)

This is a working copy of [Cilium](https://github.com/cilium/cilium) being incrementally
**ported to Windows**, where the Linux eBPF datapath is replaced by the CNC datapath
(via the `cncshim` CNC API). Use these notes to stay consistent with the established
patterns.

## Project shape
- Go module `github.com/cilium/cilium` (Go 1.26+). Agent is assembled from **Hive cells**
  (`daemon/cmd/cells.go`): `Infrastructure` + `ControlPlane` + `datapath.Cell`.
- Data flows via **StateDB**: reflectors write desired state into tables; reconcilers
  (`statedb/reconciler`, `reconciler.Operations[T]`) apply it to the datapath.

## Windows port conventions (IMPORTANT)
- **Split Linux-only files by build tag.** Keep platform-neutral types/interfaces in an
  untagged file; put the Linux implementation in `*_linux.go` (`//go:build linux`) and the
  Windows implementation in `*_windows.go` (`//go:build windows`).
- **Build tag placement**: 2-line SPDX/Copyright header, blank line, `//go:build <os>`,
  blank line, then `package ...`.
- **Windows datapath = CNC**, not eBPF. Where CNC has no equivalent (rev-nat, affinity,
  maglev, source-range, skip-LB, sysctl, TPROXY, BPF pressure metrics), implement a
  **logged placeholder** ("<feature> not implemented ... on Windows") and, where callers
  expect bookkeeping, keep an in-memory fallback (mirror Linux byte-order semantics).
- **cncshim**: `github.com/princepereira/cncshim/pkg/cncapi` (vendored). It is `// indirect`
  in `go.mod` — a `go mod tidy` under `GOOS=linux` (CI default) will DROP it and break the
  Windows build. Flag this if touching module files.
- **Line endings**: new files must be **LF**, not CRLF (`create_file` on Windows writes
  CRLF; normalize before `gofmt`).

## Build / validate
- Native host is Windows, so `go build ./<pkg>` uses `GOOS=windows`. Cross-check Linux with
  `$env:GOOS='linux'; go build ./<pkg>; Remove-Item Env:\GOOS`.
- The full `pkg/loadbalancer/maps` dependency tree is Linux-only today; whole-package
  Windows builds still fail on pre-existing transitive deps — only verify the files you add.
- **gopls locks `vendor/`.** Before `go mod vendor`, stop it:
  `Get-Process gopls -ErrorAction SilentlyContinue | Stop-Process -Force`. Never interrupt
  `go mod vendor` (the tree is huge and legitimately slow).

## Work done so far (this port)
- `pkg/loadbalancer/maps`: `lbmaps_linux.go` + `lbmaps_windows.go` (`CNCLBMaps` embeds
  `FakeLBMaps`, CNC-backed `UpdateService`/`UpdateBackend`, placeholders for the rest);
  `pressure_metrics_{linux,windows}.go`; `skiplb_{linux,windows}.go` (Windows = in-memory).
- `pkg/fqdn/proxy/ipfamily`: split into untagged struct + `ipfamily_{linux,windows}.go`.
  Windows uses `windows.IPPROTO_IP/IPPROTO_IPV6`; `IP_TRANSPARENT`/`IP_RECVORIGDSTADDR`
  have no Windows equivalent (WFP would be needed) → set to 0.

## Pending / known gaps
- `pkg/fqdn/dnsproxy` consumers of the TPROXY options are still Linux-only (raw sockets,
  `SO_MARK`, cmsg) — needs a Windows port or build-tagged stub.
- Reconcilers with Linux deps: BPF/LB/skip-LB/subnet/bwmap (eBPF), device/route/neighbor/
  bandwidth (netlink), ipset (iptables), sysctl (procfs), ztunnel (netns). Platform-neutral:
  `ciliumenvoyconfig`, `dynamiclifecycle`.

## Reference docs (workspace root)
- `cilium-agent-reconcilers.md` — all StateDB reconcilers + Linux dependency table.
- `cilium-agent-lifecycles.md` (+ `.pdf`) — FQDN / endpoint / load-balancer sequence diagrams.
- `cilium-lb-dataflow.md` — reflector → writer → StateDB → reconciler → eBPF maps trace.

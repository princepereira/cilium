<overview>
The user wants to make `cilium-agent` build and run on Windows nodes while preserving Linux functionality. The strategy is to separate Linux-specific code from platform-neutral code using Go build tags (`_linux.go` / `_windows.go` / `_unspecified.go` files), providing Windows implementations (best-effort via public libs) or dummy/error stubs where real functionality isn't feasible yet. The user specified using cncshim (ebpf maps), microsoft/hnslib (network components), microsoft/hcsshim (containers), and abstract functions across platform files for runtime Windows implementations — though the current phase is focused on getting a compile.
</overview>

<history>
1. The user asked to make cilium-agent build and run for Windows nodes, using cncshim/hnslib/hcsshim and abstract `*_linux.go`/`*_windows.go` functions.
   - Explored the repo: this is the Cilium codebase, git branch `ppereira-linux-windows-separation`, working tree clean, at upstream `main` (merge-base = HEAD commit `2deb5d25bc`). No prior non-vendor `_windows.go` files existed — essentially a fresh port.
   - Attempted `GOOS=windows go build ./daemon` — revealed 17 first-level failing packages (Go reports errors only for packages whose dependencies compiled, so fixing frontier reveals next layer iteratively).
   - Identified error categories: missing `unix.*`/`netlink.*`/`link.*` constants, Linux-only netlink/ebpf datapath calls, `renameio` (exports nothing on Windows), `go-iptables` (Linux-only), `go-osstat/memory` field differences, `version.GetKernelVersion`.
   - Established the repo's existing convention: `_linux.go` (real) + `_unspecified.go` (`//go:build !linux`) stubs, and discovered pre-existing `route_darwin.go`/`sysctl_darwin.go` darwin stubs.
   - Fixed the first frontier (~15 packages) with build-tag splits and vendored shims, committed as commit `2fe255022a`.
   - Rebuilt: frontier shrank to 9 packages, revealing new ones (common/ipsec, datapath/iptables, k8s/hostfirewallbypass, routing) plus still-pending datapath packages.
   - Added netlink `FAMILY_*`/`SCOPE_*` constant shim and iptables `sysctl_windows.go`; validated route+iptables compile; committed.
   - Was mid-way through viewing the next batch (hostfirewallbypass, xdp) when compaction occurred.
</history>

<work_done>
Files created (Windows/stub/platform files):
- `pkg/version/version_windows.go` — GetKernelVersion returns error on Windows
- `pkg/ztunnel/iptables/inpod_windows.go` — CreateInPodRules/DeleteInPodRules stubs (returns error)
- `pkg/fqdn/proxy/ipfamily/ipfamily_linux.go` + `ipfamily_unspecified.go` — socket-opt constants (real / zero)
- `pkg/monitor/agent/listener/listener_linux.go` + `listener_unspecified.go` — IsDisconnected (unix.Errno / syscall.Errno)
- `pkg/datapath/linux/linux_defaults/linux_defaults_linux.go` + `_unspecified.go` — rtProtoKernel const (2)
- `pkg/loadbalancer/reflectors/cell_linux.go` + `cell_unspecified.go` — NetnsCookieSupportFunc
- `pkg/datapath/linux/netdevice/netdevice_unspecified.go` — address-lookup stubs
- `pkg/loadinfo/loadinfo_linux.go` + `loadinfo_unspecified.go` — LogCurrentSystemLoad (full / reduced)
- `pkg/datapath/link/link_linux.go` + `link_unspecified.go` — addAltName helper
- `pkg/datapath/linux/route/route_windows.go` — full Windows stub (Rule type, MainTable/RTN_LOCAL/etc consts, all netlink funcs return errUnsupported)
- `pkg/datapath/iptables/sysctl_windows.go` — enableIPForwarding no-op
- `vendor/github.com/vishvananda/netlink/netlink_constants_others.go` — FAMILY_*/SCOPE_* for `!linux`
- `vendor/golang.org/x/sys/unix/cilium_bpf_flags_windows.go` — BPF_F_NO_PREALLOC/NO_COMMON_LRU/RDONLY_PROG for windows

Files modified:
- `pkg/datapath/linux/safenetlink/netlink_unspecified.go` — added WithRetry + WithRetryResult
- `pkg/fqdn/proxy/ipfamily/ipfamily.go` — use package vars instead of unix consts
- `pkg/monitor/agent/listener/listener.go` — removed IsDisconnected + unix import
- `pkg/datapath/linux/linux_defaults/linux_defaults.go` — RTProto uses rtProtoKernel, removed unix import
- `pkg/loadbalancer/reflectors/cell.go` — removed NetnsCookieSupportFunc + imports
- `pkg/loadinfo/loadinfo.go` — removed Linux-only funcs + imports
- `pkg/datapath/link/link.go` — AddAltName calls addAltName helper
- `pkg/datapath/linux/netdevice/netdevice.go` — added `//go:build linux`
- `pkg/ztunnel/iptables/inpod.go` — added `//go:build linux`
- `vendor/github.com/google/renameio/v2/{option,tempfile,writefile}.go` — removed `//go:build !windows` (os.Rename replaces on Windows)

Work completed:
- [x] First frontier (~15 packages) fixed + committed (`2fe255022a`)
- [x] Second batch: netlink constant shim, route_windows.go, iptables sysctl_windows.go — validated route+iptables compile
- [ ] NOT YET committed: route_windows.go, netlink_constants_others.go, iptables/sysctl_windows.go (staged/created after the commit — need to verify git state; commit `2fe255022a` included route_windows.go, netlink shim, unix shim per the staged list, but sysctl_windows.go was created AFTER commit and is uncommitted)
- [ ] Remaining frontier packages: hostfirewallbypass, common/ipsec, xdp, probes, bandwidth, device, routing, route/reconciler
- [ ] The core `pkg/datapath/linux` package (~2900 lines, node.go/ipsec.go etc.) — the major remaining wall
</work_done>

<technical_details>
- Build strategy is iterative: `GOOS=windows GOARCH=amd64 go build ./daemon` reveals one layer of failing packages at a time; fix, rebuild, repeat.
- Convention: `*_linux.go` (real, `//go:build linux`) + `*_unspecified.go` (`//go:build !linux`) or `*_windows.go`. Use `_unspecified` (!linux) when darwin/other should also get the stub; use `_windows` when specifically windows.
- `golang.org/x/sys/unix` DOES build on Windows but is nearly empty (only endian_little.go + vgetrandom_unsupported.go compile) — hence "undefined: unix.X" errors, not "package excluded". Adding Windows-tagged constant files to vendored unix is the chosen shim approach for stable Linux-ABI constants.
- `renameio/v2` upstream exports NOTHING on Windows by design (atomicity/chmod concerns). Fix: removed `//go:build !windows` from the 3 vendored files — `os.Rename` replaces existing files on Windows (Go uses MoveFileEx REPLACE_EXISTING), so it compiles and works best-effort.
- `go-iptables` (Linux-only, uses syscall.Flock, int-vs-syscall.Handle) is pulled in ONLY via `pkg/ztunnel/iptables/inpod.go`. Fixed by build-tagging inpod.go to linux + windows stub — avoids patching the vendored lib. Only CreateInPodRules/DeleteInPodRules are used externally (by pkg/ztunnel/zds/server.go).
- `go-osstat/memory` Stats struct differs per platform; Total/Used/Free exist on ALL platforms (linux/darwin/windows/other), so the !linux loadinfo uses only those.
- vishvananda/netlink: `type Scope uint8` is in shared route.go; SCOPE_* and FAMILY_* constants are only in `_linux.go` files. Added `netlink_constants_others.go` (`!linux`) with ABI values: FAMILY_ALL=0,V4=2,V6=10,MPLS=28; SCOPE_UNIVERSE=0,SITE=200,LINK=253,HOST=254,NOWHERE=255.
- `route.Rule` type + `MainTable` const live in route_linux.go; route.go (shared) only has the `Route` type. route_windows.go duplicates Rule/MainTable/consts + stubs all funcs (Lookup, Upsert, Delete, ReplaceRule, ReplaceRuleIPv6, DeleteRule, ListRules, DeleteRouteTable, NodeDeviceWithDefaultRoute) returning errUnsupported. NodeDeviceWithDefaultRoute uses the LINUX signature (with logger) since callers pass logger (darwin stub's signature differs/is stale).
- CRITICAL SCOPE REALITY: The daemon imports `pkg/datapath/linux` (LinuxDatapath), a ~2900-line netlink/bpf-heavy package. Full Windows compile requires either heavily stubbing it OR build-tagging the whole package linux + providing a Windows datapath cell. This is the major remaining architectural effort. Many frontier packages (routing, node.go, ipsec.go) are consumers of this core.
- Remaining frontier packages use netlink FUNCTIONS/methods/linux-only-struct-fields (netlink.Via, RuleDel, QdiscReplace, FilterReplace, LinkModify, XfrmState.Aead/Auth/Crypt, XfrmMark) and ebpf `link` package attach funcs (link.AttachCgroup/AttachTCX/XDPAttachFlags) — these need per-package linux-tag + windows stubs (constants shim alone won't fix them).
- hostfirewallbypass/bypass.go uses unix.SetsockoptUint64/SOL_SOCKET/SO_MARK (a function + consts) — needs linux-tag + windows stub (setProxyEgressMark).
</technical_details>

<important_files>
- `pkg/datapath/linux/route/route_windows.go` (created)
   - Foundational; unblocked routing/reconciler/ztunnel/vtep/node/ipsec consumers. Full Windows stub of route_linux.go's public API.
- `vendor/github.com/vishvananda/netlink/netlink_constants_others.go` (created)
   - High-leverage `!linux` shim for FAMILY_*/SCOPE_* used across many packages.
- `vendor/golang.org/x/sys/unix/cilium_bpf_flags_windows.go` (created)
   - Windows BPF flag constants for generated datapath map specs (maps_generated.go).
- `pkg/datapath/iptables/sysctl_windows.go` (created, possibly uncommitted)
   - enableIPForwarding no-op; iptables package also needs netlink FAMILY consts (now shimmed).
- `pkg/datapath/xdp/xdp.go` (viewed, NOT yet fixed)
   - Uses link.XDPAttachFlags/XDPDriverMode/XDPGenericMode at lines ~145-150. Has cross-platform consts (AccelerationMode/Mode strings) at top that must stay shared.
- `pkg/k8s/hostfirewallbypass/bypass.go` (viewed, NOT yet fixed)
   - setProxyEgressMark (lines ~40-50) uses unix.SetsockoptUint64/SOL_SOCKET/SO_MARK — needs platform split.
- `pkg/datapath/linux` (node.go, ipsec.go, etc.) — the major remaining wall, 8 non-test files, only devices_controller.go is already `//go:build linux`.
</important_files>

<next_steps>
Remaining work (fix + rebuild + commit iteratively):
1. Verify git state — ensure `pkg/datapath/iptables/sysctl_windows.go` and any post-commit files are committed (`git status`).
2. Fix current frontier packages with linux-tag + windows stub:
   - `pkg/k8s/hostfirewallbypass/bypass.go` — split setProxyEgressMark (linux uses unix.Setsockopt; windows no-op/error)
   - `pkg/datapath/xdp/xdp.go` — move link.XDP* usages into linux file, windows stub
   - `pkg/datapath/linux/probes` — large package (attach_cgroup.go, attach_type.go, probes.go); check exported surface/consumers before stubbing (widely used for feature probing)
   - `pkg/datapath/linux/bandwidth/ops.go` — Manager, netlink.QdiscReplace, FqDefault* (check if Manager is in a linux file)
   - `pkg/datapath/linux/device/reconciler.go` — netlink.Handle.LinkModify/Close usage
   - `pkg/common/ipsec/utils.go` — netlink.XfrmState fields (Aead/Auth/Crypt), netlink.XfrmMark
   - `pkg/datapath/linux/routing/routing.go` — netlink funcs + unix.RTN_UNREACHABLE/IFF_SLAVE
   - `pkg/datapath/linux/route/reconciler/reconciler.go` — netlink.Via, nl.FAMILY_V4/V6, netlink.FAMILY_ALL, netlink.SCOPE_HOST
3. Then tackle the core `pkg/datapath/linux` package and subsequent layers.

Immediate next step: Continue viewing/fixing hostfirewallbypass and xdp (was mid-view). Rebuild `GOOS=windows go build ./daemon` after each batch to track frontier. Commit periodically.

IMPORTANT: Be honest with the user about scope — full Windows build+run is a large multi-stage effort (the datapath core + a Windows datapath implementation via hnslib remain). Consider giving a status report and roadmap. Use `GOOS=windows`/`GOARCH=amd64` env vars set per-command (they don't persist across powershell calls). Clean up temp files (build_errors*.txt, *.exe) before commits.
</next_steps>
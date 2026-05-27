# Cilium Windows Datapath

This package implements the Windows datapath for the Cilium agent, using
[cncshim](https://github.com/princepereira/cncshim) to program load-balancer
rules via the CNC API.

## Building

```powershell
# From the repository root:
go mod tidy
go mod vendor
go build -mod=vendor -o cilium-agent.exe ./daemon/
```

## Prerequisites

The following must be present on the target Windows node:

- **eBPF drivers**: `ebpfcore` and `netebpfext` services must be running.
- **ebpfapi.dll**: Must be in `C:\Windows\System32`.
- **cncapi.dll**: Must be accessible to the agent binary.
- **HNS service**: `hns` service must be running.
- **Test signing** (if using test-signed drivers): `bcdedit /set testsigning on` + reboot.

## Enabling Cilium on Windows (HNS integration)

Set the registry key and restart HNS:

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\hns\State" `
    -Name "CiliumOnWindows" -Value 1 -PropertyType DWORD -Force
Restart-Service hns -Force
```

To disable:

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\hns\State" `
    -Name "CiliumOnWindows" -Value 0
Restart-Service hns -Force
```

<#
.SYNOPSIS
    Dump Cilium eBPF-for-Windows datapath state to human-readable text files.

.DESCRIPTION
    Writes two files in the output directory:
      * ebpfstate.txt - raw (already-decoded) output of every 'ebpf_state.exe show <type>'.
      * bpftool.txt   - 'bpftool.exe map show' plus, for the load-balancer maps, a DECODED
                        table (decimal IPs / ports / ids / rev-nat), followed by the raw dumps.

    Run on the Windows node where ebpf-for-windows + cilium-agent are installed.

.EXAMPLE
    .\Dump-CiliumState.ps1
    .\Dump-CiliumState.ps1 -OutDir C:\temp -Filter 10.0.130.240
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Get-Location).Path,
    [string]$Bpftool = "bpftool.exe",
    [string]$EbpfState = "ebpf_state.exe",
    [string]$Filter               # optional: only decode entries whose IP matches this (e.g. 10.0.130.240)
)

$ErrorActionPreference = "Continue"
$bpfOut   = Join-Path $OutDir "bpftool.txt"
$stateOut = Join-Path $OutDir "ebpfstate.txt"
$proto = @{ 0 = "any"; 1 = "ICMP"; 6 = "TCP"; 17 = "UDP"; 58 = "ICMPv6" }

# ---------- byte helpers ----------------------------------------------------
function ConvertTo-Bytes([string[]]$tokens) {
    # accepts "0x0a" / "0a" / "10" (decimal from some builds is rare; assume hex)
    $out = New-Object System.Collections.Generic.List[int]
    foreach ($t in $tokens) {
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $h = $t.Trim() -replace '^0x',''
        [void]$out.Add([Convert]::ToInt32($h,16))
    }
    return ,$out.ToArray()
}
function IPv4([int[]]$b,[int]$o=0) { "$($b[$o]).$($b[$o+1]).$($b[$o+2]).$($b[$o+3])" }
function BE16([int[]]$b,[int]$o)   { ($b[$o] -shl 8) -bor $b[$o+1] }
function LE16([int[]]$b,[int]$o)   { $b[$o] -bor ($b[$o+1] -shl 8) }
function LE32([int[]]$b,[int]$o)   { $b[$o] -bor ($b[$o+1] -shl 8) -bor ($b[$o+2] -shl 16) -bor ($b[$o+3] -shl 24) }
function IPv6([int[]]$b,[int]$o=0) {
    $parts = for ($i=0; $i -lt 16; $i+=2) { '{0:x2}{1:x2}' -f $b[$o+$i], $b[$o+$i+1] }
    ($parts -join ':')
}
function Pn([int]$p) { if ($proto.ContainsKey($p)) { $proto[$p] } else { "proto$p" } }

# ---------- map dump (JSON first, text fallback) ----------------------------
function Get-MapId([string]$fullName) {
    # match on the (possibly 15-char truncated) name shown by 'map show'
    $short = if ($fullName.Length -gt 15) { $fullName.Substring(0,15) } else { $fullName }
    $line = & $Bpftool map show 2>$null | Select-String ([regex]::Escape($short)) | Select-Object -First 1
    if ($line) { return ($line.ToString().Split(':')[0].Trim()) }
    return $null
}
function Get-MapEntries([string]$fullName) {
    # returns array of @{ Key=int[]; Value=int[] }
    $entries = @()
    $json = & $Bpftool -j map dump name $fullName 2>$null
    if ($LASTEXITCODE -eq 0 -and $json) {
        try {
            foreach ($e in ($json | ConvertFrom-Json)) {
                if ($null -ne $e.key) {
                    $entries += @{ Key = (ConvertTo-Bytes $e.key); Value = (ConvertTo-Bytes $e.value) }
                }
            }
            return $entries
        } catch { }
    }
    # text fallback (by name, then by id)
    $txt = & $Bpftool map dump name $fullName 2>$null
    if (-not $txt) {
        $id = Get-MapId $fullName
        if ($id) { $txt = & $Bpftool map dump id $id 2>$null }
    }
    foreach ($l in $txt) {
        if ($l -match '^key:\s*(.+?)\s+value:\s*(.+)$') {
            $entries += @{
                Key   = (ConvertTo-Bytes ($matches[1] -split '\s+'))
                Value = (ConvertTo-Bytes ($matches[2] -split '\s+'))
            }
        }
    }
    return $entries
}
function Match-Filter([string]$ip) {
    if ([string]::IsNullOrWhiteSpace($Filter)) { return $true }
    return $ip -eq $Filter
}

# ---------- decoders --------------------------------------------------------
function Decode-Services([string]$name,[bool]$v6) {
    $rows = @()
    foreach ($e in (Get-MapEntries $name)) {
        $k = $e.Key; $v = $e.Value
        if ($v6) { $vip = IPv6 $k 0; $off = 16 } else { $vip = IPv4 $k 0; $off = 4 }
        $port  = BE16 $k $off
        $slot  = LE16 $k ($off+2)
        $pr    = $k[$off+4]
        $scope = $k[$off+5]
        $backendId = LE32 $v 0
        $count     = LE16 $v 4
        $revnat    = LE16 $v 6
        $flags     = $v[8]; $flags2 = $v[9]
        if (-not (Match-Filter $vip)) { continue }
        $kind = if ($slot -eq 0 -and $port -ne 0) { "MASTER" }
                elseif ($slot -eq 0 -and $port -eq 0) { "wildcard" }
                else { "slot$slot" }
        $rows += [pscustomobject]@{
            VIP=$vip; Port=$port; Proto=(Pn $pr); Scope=$scope; Entry=$kind
            BackendId = if ($kind -like "slot*") { $backendId } else { "" }
            Backends  = if ($kind -eq "MASTER") { $count } else { "" }
            RevNat=$revnat; Flags=$flags; Flags2=$flags2
        }
    }
    return $rows | Sort-Object VIP, Port, Entry
}
function Decode-Backends([string]$name,[bool]$v6) {
    $rows = @()
    foreach ($e in (Get-MapEntries $name)) {
        $k = $e.Key; $v = $e.Value
        $id = LE32 $k 0
        if ($v6) { $addr = IPv6 $v 0; $off = 16 } else { $addr = IPv4 $v 0; $off = 4 }
        $port = BE16 $v $off; $pr = $v[$off+2]; $flags = $v[$off+3]
        if (-not (Match-Filter $addr)) { continue }
        $rows += [pscustomobject]@{ BackendId=$id; Address=$addr; Port=$port; Proto=(Pn $pr); Flags=$flags }
    }
    return $rows | Sort-Object BackendId
}
function Decode-RevNat([string]$name,[bool]$v6) {
    $rows = @()
    foreach ($e in (Get-MapEntries $name)) {
        $k = $e.Key; $v = $e.Value
        $idx = LE16 $k 0
        if ($v6) { $addr = IPv6 $v 0; $off = 16 } else { $addr = IPv4 $v 0; $off = 4 }
        $port = BE16 $v $off
        if (-not (Match-Filter $addr)) { continue }
        $rows += [pscustomobject]@{ RevNatIndex=$idx; VIP=$addr; Port=$port }
    }
    return $rows | Sort-Object RevNatIndex
}

# ---------- write bpftool.txt ----------------------------------------------
function Section($title) { "`r`n============================================================`r`n $title`r`n============================================================" }

"Cilium eBPF-for-Windows datapath dump (bpftool)"                | Set-Content $bpfOut
"Generated: $(Get-Date -Format s)   Node: $env:COMPUTERNAME"     | Add-Content $bpfOut
if ($Filter) { "Filter: $Filter" | Add-Content $bpfOut }

Section "map show (all pinned maps)"        | Add-Content $bpfOut
(& $Bpftool map show 2>&1 | Out-String)     | Add-Content $bpfOut

$decodeSets = @(
    @{ Title="LB4 SERVICES (decoded)";  Fn={ Decode-Services "cilium_lb4_services" $false } },
    @{ Title="LB4 BACKENDS (decoded)";  Fn={ Decode-Backends "cilium_lb4_backends" $false } },
    @{ Title="LB4 REVERSE NAT (decoded)";Fn={ Decode-RevNat  "cilium_lb4_reverse_nat" $false } },
    @{ Title="LB6 SERVICES (decoded)";  Fn={ Decode-Services "cilium_lb6_services" $true } },
    @{ Title="LB6 BACKENDS (decoded)";  Fn={ Decode-Backends "cilium_lb6_backends" $true } },
    @{ Title="LB6 REVERSE NAT (decoded)";Fn={ Decode-RevNat  "cilium_lb6_reverse_nat" $true } }
)
foreach ($s in $decodeSets) {
    Section $s.Title | Add-Content $bpfOut
    $rows = & $s.Fn
    if ($rows) { ($rows | Format-Table -AutoSize | Out-String) | Add-Content $bpfOut }
    else       { "(no entries)" | Add-Content $bpfOut }
}

# raw dumps for reference / other maps
$rawMaps = @(
    "cilium_lb4_services","cilium_lb4_backends","cilium_lb4_reverse_nat",
    "cilium_lb6_services","cilium_lb6_backends","cilium_lb6_reverse_nat",
    "cilium_lxc","cilium_ipcache"
)
Section "RAW dumps (bpftool map dump name ...)" | Add-Content $bpfOut
foreach ($m in $rawMaps) {
    "`r`n--- $m ---" | Add-Content $bpfOut
    $d = & $Bpftool map dump name $m 2>&1 | Out-String
    if (-not $d.Trim()) {
        $id = Get-MapId $m
        if ($id) { "(by id $id)" | Add-Content $bpfOut; $d = & $Bpftool map dump id $id 2>&1 | Out-String }
    }
    if ($d.Trim()) { $d | Add-Content $bpfOut } else { "(empty / not present)" | Add-Content $bpfOut }
}

# ---------- write ebpfstate.txt --------------------------------------------
"Cilium eBPF-for-Windows datapath dump (ebpf_state)"            | Set-Content $stateOut
"Generated: $(Get-Date -Format s)   Node: $env:COMPUTERNAME"    | Add-Content $stateOut
if ($Filter) { "Filter: $Filter" | Add-Content $stateOut }

$stateTypes = @(
    "loadbalancers","rev_nat","maglev",
    "ct","snat","ipcache","endpoints","policymap",
    "masq","nodeport_neighbors","node_config","node_devices","observability_config"
)
foreach ($t in $stateTypes) {
    Section "ebpf_state show $t" | Add-Content $stateOut
    if ($Filter) { $o = & $EbpfState show $t filter $Filter 2>&1 }
    else         { $o = & $EbpfState show $t 2>&1 }
    ($o | Out-String) | Add-Content $stateOut
}

Write-Host "Wrote:"
Write-Host "  $bpfOut"
Write-Host "  $stateOut"

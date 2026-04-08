#Requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'ByHosts')]
param (
    

    [Parameter(
        ParameterSetName  = 'ByHosts',
        Mandatory         = $true,
        HelpMessage       = 'One or more hostnames or IP addresses to scan.'
    )]
    [ValidateNotNullOrEmpty()]
    [string[]] $Hosts,

    [Parameter(
        ParameterSetName  = 'BySubnet',
        Mandatory         = $true,
        HelpMessage       = 'Subnet in CIDR notation, e.g. 192.168.1.0/24.'
    )]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')]
    [string] $Subnet,


    [Parameter(HelpMessage = 'TCP ports to probe on each host.')]
    [ValidateRange(1, 65535)]
    [int[]] $Ports = @(80, 443),

    [Parameter(HelpMessage = 'ICMP ping timeout in milliseconds.')]
    [ValidateRange(100, 30000)]
    [int] $PingTimeout = 1000,

    [Parameter(HelpMessage = 'TCP connection timeout in milliseconds.')]
    [ValidateRange(100, 30000)]
    [int] $PortTimeout = 500,


    [Parameter(HelpMessage = 'Path for CSV output file.')]
    [string] $OutputCSV,

    [Parameter(HelpMessage = 'Path for HTML output file.')]
    [string] $OutputHTML,


    [Parameter(HelpMessage = 'Enable parallel scanning (PowerShell 7+).')]
    [switch] $Parallel,

    [Parameter(HelpMessage = 'Max concurrent threads for parallel scanning.')]
    [ValidateRange(1, 256)]
    [int] $ThrottleLimit = 50,


    [Parameter(HelpMessage = 'Only report hosts that responded to ping.')]
    [switch] $OnlineOnly,

    [Parameter(HelpMessage = 'Only report hosts with at least one open port.')]
    [switch] $OpenPortsOnly
)


function Write-NPInfo {
    [CmdletBinding()]
    param([string] $Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [INFO]  $Message" -ForegroundColor Cyan
}

function Write-NPSuccess {
    [CmdletBinding()]
    param([string] $Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [OK]    $Message" -ForegroundColor Green
}

function Write-NPWarning {
    [CmdletBinding()]
    param([string] $Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [WARN]  $Message" -ForegroundColor Yellow
}

function Write-NPError {
    [CmdletBinding()]
    param([string] $Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$ts] [ERROR] $Message" -ForegroundColor Red
}

function Write-NPHostResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Result
    )

    $statusColor = if ($Result.PingOnline) { 'Green' } else { 'Red' }
    $statusText  = if ($Result.PingOnline) { 'ONLINE ' } else { 'OFFLINE' }

    Write-Host ('  [{0}] {1,-45} Ping:{2}ms  Ports: {3}' -f
        $statusText,
        $Result.Host,
        ($Result.PingLatencyMs ?? '-'),
        $Result.PortResults
    ) -ForegroundColor $statusColor
}


function Test-NetworkPointerPing {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string] $HostName,

        [ValidateRange(100, 30000)]
        [int] $TimeoutMs = 1000
    )

    $result = [PSCustomObject]@{
        Host      = $HostName
        Online    = $false
        LatencyMs = $null
    }

    try {
        $ping  = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send($HostName, $TimeoutMs)

        if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $result.Online    = $true
            $result.LatencyMs = [int]$reply.RoundtripTime
        }
    }
    catch {
    }
    finally {
        if ($ping) { $ping.Dispose() }
    }

    return $result
}

function Test-NetworkPointerTCPPort {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string] $HostName,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int] $Port,

        [ValidateRange(100, 30000)]
        [int] $TimeoutMs = 500
    )

    $portResult = [PSCustomObject]@{
        Port   = $Port
        Open   = $false
        Banner = ''
    }

    try {
        $client      = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $client.ConnectAsync($HostName, $Port)

        if ($connectTask.Wait($TimeoutMs)) {
            $portResult.Open = $client.Connected
        }
    }
    catch {
    }
    finally {
        if ($client) { $client.Dispose() }
    }

    return $portResult
}

function Expand-NetworkPointerSubnet {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')]
        [string] $Subnet
    )

    $parts        = $Subnet -split '/'
    $networkAddr  = $parts[0]
    $prefixLength = [int]$parts[1]

    if ($prefixLength -lt 8 -or $prefixLength -gt 30) {
        throw "Subnet prefix length /$prefixLength is outside the supported range /8–/30."
    }

    $octets = $networkAddr -split '\.'
    foreach ($octet in $octets) {
        $val = [int]$octet
        if ($val -lt 0 -or $val -gt 255) {
            throw "Invalid IP octet '$octet' in subnet '$Subnet'."
        }
    }

    try {
        $ipObj       = [System.Net.IPAddress]::Parse($networkAddr)
        $ipBytes     = $ipObj.GetAddressBytes()

        if ([System.BitConverter]::IsLittleEndian) {
            [Array]::Reverse($ipBytes)
        }
        $ipInt32 = [System.BitConverter]::ToUInt32($ipBytes, 0)

        $maskInt32  = [uint32](0xFFFFFFFF -shl (32 - $prefixLength))
        $hostCount  = [math]::Pow(2, 32 - $prefixLength) - 2   # exclude network + broadcast
        $networkInt = $ipInt32 -band $maskInt32

        $addresses = [System.Collections.Generic.List[string]]::new()

        for ($i = 1; $i -le $hostCount; $i++) {
            $hostInt  = $networkInt + [uint32]$i
            $hostBytes = [System.BitConverter]::GetBytes($hostInt)

            if ([System.BitConverter]::IsLittleEndian) {
                [Array]::Reverse($hostBytes)
            }

            $addresses.Add(([System.Net.IPAddress]::new($hostBytes)).ToString())
        }

        return $addresses.ToArray()
    }
    catch {
        throw "Failed to expand subnet '$Subnet': $_"
    }
}

function Invoke-NetworkPointerHostScan {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [string] $HostName,

        [int[]] $Ports = @(80, 443),

        [int] $PingTimeoutMs = 1000,

        [int] $PortTimeoutMs = 500
    )

    $timestamp = Get-Date

    $pingResult = Test-NetworkPointerPing -HostName $HostName -TimeoutMs $PingTimeoutMs

    $portDetails = foreach ($port in $Ports) {
        Test-NetworkPointerTCPPort -HostName $HostName -Port $port -TimeoutMs $PortTimeoutMs
    }

    $portResultStr = ($portDetails | ForEach-Object {
        "$($_.Port):" + (if ($_.Open) { 'Open' } else { 'Closed' })
    }) -join ' '

    $openPorts     = ($portDetails | Where-Object Open | ForEach-Object { $_.Port }) -join ','
    $openPortCount = ($portDetails | Where-Object Open | Measure-Object).Count

    return [PSCustomObject]@{
        Timestamp     = $timestamp
        Host          = $HostName
        PingOnline    = $pingResult.Online
        PingLatencyMs = $pingResult.LatencyMs
        PortResults   = $portResultStr
        OpenPorts     = $openPorts
        TotalPorts    = $Ports.Count
        OpenPortCount = $openPortCount
    }
}

function Invoke-NetworkPointerScan {
       [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory)]
        [string[]] $TargetHosts,

        [int[]] $Ports          = @(80, 443),
        [int]   $PingTimeoutMs  = 1000,
        [int]   $PortTimeoutMs  = 500,
        [bool]  $RunParallel    = $false,
        [int]   $ThrottleLimit  = 50
    )

    if ($RunParallel) {
        $results = $TargetHosts | ForEach-Object -Parallel {
            function Test-NetworkPointerPing {
                param([string]$HostName, [int]$TimeoutMs = 1000)
                $r = [PSCustomObject]@{ Host = $HostName; Online = $false; LatencyMs = $null }
                try {
                    $ping  = [System.Net.NetworkInformation.Ping]::new()
                    $reply = $ping.Send($HostName, $TimeoutMs)
                    if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                        $r.Online    = $true
                        $r.LatencyMs = [int]$reply.RoundtripTime
                    }
                } catch {} finally { if ($ping) { $ping.Dispose() } }
                return $r
            }

            function Test-NetworkPointerTCPPort {
                param([string]$HostName, [int]$Port, [int]$TimeoutMs = 500)
                $pr = [PSCustomObject]@{ Port = $Port; Open = $false; Banner = '' }
                try {
                    $client = [System.Net.Sockets.TcpClient]::new()
                    $task   = $client.ConnectAsync($HostName, $Port)
                    if ($task.Wait($TimeoutMs)) { $pr.Open = $client.Connected }
                } catch {} finally { if ($client) { $client.Dispose() } }
                return $pr
            }

            $hostName      = $_
            $ports         = $using:Ports
            $pingTimeout   = $using:PingTimeoutMs
            $portTimeout   = $using:PortTimeoutMs

            $timestamp   = Get-Date
            $pingResult  = Test-NetworkPointerPing -HostName $hostName -TimeoutMs $pingTimeout
            $portDetails = foreach ($p in $ports) {
                Test-NetworkPointerTCPPort -HostName $hostName -Port $p -TimeoutMs $portTimeout
            }

            $portStr       = ($portDetails | ForEach-Object { "$($_.Port):" + (if ($_.Open) { 'Open' } else { 'Closed' }) }) -join ' '
            $openPortsList = ($portDetails | Where-Object Open | ForEach-Object { $_.Port }) -join ','
            $openCount     = ($portDetails | Where-Object Open | Measure-Object).Count

            [PSCustomObject]@{
                Timestamp     = $timestamp
                Host          = $hostName
                PingOnline    = $pingResult.Online
                PingLatencyMs = $pingResult.LatencyMs
                PortResults   = $portStr
                OpenPorts     = $openPortsList
                TotalPorts    = $ports.Count
                OpenPortCount = $openCount
            }

        } -ThrottleLimit $ThrottleLimit

        return $results
    }
    else {
        $results = foreach ($h in $TargetHosts) {
            Invoke-NetworkPointerHostScan `
                -HostName      $h `
                -Ports         $Ports `
                -PingTimeoutMs $PingTimeoutMs `
                -PortTimeoutMs $PortTimeoutMs
        }
        return $results
    }
}

function Export-NetworkPointerCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]] $Results,

        [Parameter(Mandatory)]
        [string] $Path
    )

    try {
        $dir = Split-Path $Path -Parent
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $Results |
            Select-Object `
                @{ Name = 'Timestamp';     Expression = { $_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } },
                Host, PingOnline, PingLatencyMs, PortResults, OpenPorts, TotalPorts, OpenPortCount |
            Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

        Write-NPSuccess "CSV report written to: $Path"
    }
    catch {
        Write-NPError "Failed to write CSV to '$Path': $_"
    }
}

function Export-NetworkPointerHTML {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]] $Results,

        [Parameter(Mandatory)]
        [string] $Path,

        [string] $ScanTitle = 'NetworkPointer — Scan Report'
    )

    try {
        $dir = Split-Path $Path -Parent
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $totalHosts   = $Results.Count
        $onlineHosts  = ($Results | Where-Object PingOnline).Count
        $offlineHosts = $totalHosts - $onlineHosts
        $hostsWithOpen= ($Results | Where-Object { $_.OpenPortCount -gt 0 }).Count
        $generatedAt  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

        $rowsHtml = foreach ($r in $Results) {
            $rowClass  = if ($r.PingOnline) { 'online' } else { 'offline' }
            $statusBadge = if ($r.PingOnline) {
                '<span class="badge badge-online">Online</span>'
            } else {
                '<span class="badge badge-offline">Offline</span>'
            }
            $latency   = if ($null -ne $r.PingLatencyMs) { "$($r.PingLatencyMs) ms" } else { '—' }
            $openPorts = if ($r.OpenPorts) { $r.OpenPorts } else { '—' }
            $ts        = $r.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')

            "<tr class='$rowClass'>
                <td>$ts</td>
                <td class='host-cell'>$($r.Host)</td>
                <td>$statusBadge</td>
                <td>$latency</td>
                <td class='port-cell'>$($r.PortResults)</td>
                <td>$openPorts</td>
                <td>$($r.OpenPortCount) / $($r.TotalPorts)</td>
            </tr>"
        }

        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>$ScanTitle</title>
  <style>
    /* ── Reset & Base ─────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      font-size: 13px;
      background: #0f1117;
      color: #e0e0e0;
      line-height: 1.5;
    }

    header {
      background: linear-gradient(135deg, #1a1d2e 0%, #12141f 100%);
      border-bottom: 2px solid #00c8ff33;
      padding: 28px 40px 20px;
    }
    header h1 {
      font-size: 22px;
      font-weight: 700;
      color: #00c8ff;
      letter-spacing: 0.04em;
      margin-bottom: 4px;
    }
    header .meta { color: #6b7280; font-size: 11px; }
    header .meta span { color: #9ca3af; }

    .stats-bar {
      display: flex;
      gap: 16px;
      padding: 16px 40px;
      background: #13151f;
      border-bottom: 1px solid #1e2130;
      flex-wrap: wrap;
    }
    .stat-card {
      background: #1a1d2e;
      border: 1px solid #252840;
      border-radius: 8px;
      padding: 12px 20px;
      min-width: 120px;
      text-align: center;
    }
    .stat-card .value {
      font-size: 26px;
      font-weight: 700;
      display: block;
    }
    .stat-card .label {
      font-size: 10px;
      color: #6b7280;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .stat-card.total .value   { color: #60a5fa; }
    .stat-card.online .value  { color: #34d399; }
    .stat-card.offline .value { color: #f87171; }
    .stat-card.ports .value   { color: #f59e0b; }

    .table-wrap {
      padding: 24px 40px 40px;
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    thead th {
      background: #1a1d2e;
      color: #9ca3af;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      padding: 10px 14px;
      text-align: left;
      border-bottom: 2px solid #252840;
      white-space: nowrap;
    }
    tbody tr {
      border-bottom: 1px solid #1a1c2a;
      transition: background 0.15s;
    }
    tbody tr:hover { background: #1e2130; }
    tbody td {
      padding: 9px 14px;
      vertical-align: middle;
    }
    .host-cell { font-weight: 600; color: #93c5fd; font-family: monospace; font-size: 12px; }
    .port-cell { font-family: monospace; font-size: 11px; color: #9ca3af; }

    tr.online  { background-color: #0d1f1a; }
    tr.offline { background-color: #1f100e; }
    tr.online:hover  { background-color: #122b22; }
    tr.offline:hover { background-color: #2a1511; }

    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .badge-online  { background: #064e3b; color: #34d399; border: 1px solid #065f46; }
    .badge-offline { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }

    footer {
      padding: 16px 40px;
      border-top: 1px solid #1e2130;
      color: #374151;
      font-size: 10px;
      text-align: center;
    }
  </style>
</head>
<body>

<header>
  <h1>&#x1F4E1; $ScanTitle</h1>
  <p class="meta">Generated: <span>$generatedAt</span> &nbsp;|&nbsp; Tool: <span>NetworkPointer v1.0.0</span></p>
</header>

<div class="stats-bar">
  <div class="stat-card total">
    <span class="value">$totalHosts</span>
    <span class="label">Hosts Scanned</span>
  </div>
  <div class="stat-card online">
    <span class="value">$onlineHosts</span>
    <span class="label">Online</span>
  </div>
  <div class="stat-card offline">
    <span class="value">$offlineHosts</span>
    <span class="label">Offline</span>
  </div>
  <div class="stat-card ports">
    <span class="value">$hostsWithOpen</span>
    <span class="label">Hosts w/ Open Ports</span>
  </div>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Host</th>
        <th>Status</th>
        <th>Ping Latency</th>
        <th>Port Results</th>
        <th>Open Ports</th>
        <th>Open / Total</th>
      </tr>
    </thead>
    <tbody>
      $($rowsHtml -join "`n      ")
    </tbody>
  </table>
</div>

<footer>NetworkPointer &mdash; PowerShell 7+ Network Scanner &mdash; $generatedAt</footer>
</body>
</html>
"@

        Set-Content -Path $Path -Value $html -Encoding UTF8
        Write-NPSuccess "HTML report written to: $Path"
    }
    catch {
        Write-NPError "Failed to write HTML to '$Path': $_"
    }
}


function Select-NetworkPointerResults {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]] $Results,

        [switch] $OnlineOnly,
        [switch] $OpenPortsOnly
    )

    $filtered = $Results

    if ($OnlineOnly) {
        $filtered = $filtered | Where-Object { $_.PingOnline -eq $true }
        Write-NPInfo "Filter applied: OnlineOnly — $($filtered.Count) host(s) remaining."
    }

    if ($OpenPortsOnly) {
        $filtered = $filtered | Where-Object { $_.OpenPortCount -gt 0 }
        Write-NPInfo "Filter applied: OpenPortsOnly — $($filtered.Count) host(s) remaining."
    }

    return $filtered
}


function Show-NetworkPointerUsage {
    Write-Host ''
    Write-Host '  ----------------------------------------------------------------' -ForegroundColor Cyan
    Write-Host '  |          NetworkPointer — Network & Host Scanner             |' -ForegroundColor Cyan
    Write-Host '  |                     Version 1.0.0                            |' -ForegroundColor Cyan
    Write-Host '  ----------------------------------------------------------------' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  USAGE' -ForegroundColor Yellow
    Write-Host '  -----------------------------------------------------------------'
    Write-Host '  Scan hosts:     .\NetworkPointer.ps1 -Hosts "192.168.1.1","server.local"'
    Write-Host '  Scan subnet:    .\NetworkPointer.ps1 -Subnet "192.168.1.0/24" -Parallel'
    Write-Host '  Custom ports:   .\NetworkPointer.ps1 -Hosts "10.0.0.1" -Ports 22,80,443,3389'
    Write-Host '  CSV export:     .\NetworkPointer.ps1 -Subnet "10.0.0.0/24" -OutputCSV ".\out.csv"'
    Write-Host '  HTML report:    .\NetworkPointer.ps1 -Subnet "10.0.0.0/24" -OutputHTML ".\out.html"'
    Write-Host '  Filter online:  .\NetworkPointer.ps1 -Subnet "10.0.0.0/24" -OnlineOnly'
    Write-Host ''
    Write-Host '  PARAMETERS' -ForegroundColor Yellow
    Write-Host '  ---------------------------------------------------------------'
    Write-Host '  -Hosts         [string[]]  One or more IPs/hostnames'
    Write-Host '  -Subnet        [string]    CIDR subnet (e.g. 192.168.1.0/24)'
    Write-Host '  -Ports         [int[]]     TCP ports (default: 80, 443)'
    Write-Host '  -PingTimeout   [int]       ICMP timeout ms (default: 1000)'
    Write-Host '  -PortTimeout   [int]       TCP timeout ms  (default: 500)'
    Write-Host '  -OutputCSV     [string]    CSV output path'
    Write-Host '  -OutputHTML    [string]    HTML output path'
    Write-Host '  -Parallel      [switch]    Enable parallel scanning'
    Write-Host '  -ThrottleLimit [int]       Parallel thread limit (default: 50)'
    Write-Host '  -OnlineOnly    [switch]    Only show/save online hosts'
    Write-Host '  -OpenPortsOnly [switch]    Only show/save hosts with open ports'
    Write-Host ''
    Write-Host '  Get full help:  Get-Help .\NetworkPointer.ps1 -Full'
    Write-Host ''
}
if ($PSBoundParameters.Count -eq 0) {
    Show-NetworkPointerUsage
    exit 0
}


Write-Host ''
Write-Host '  ----------------------------------------------------------------' -ForegroundColor DarkCyan
Write-Host '  |  NetworkPointer v1.0.0 — Network & Host Scanner              |' -ForegroundColor DarkCyan
Write-Host '  ----------------------------------------------------------------' -ForegroundColor DarkCyan
Write-Host ''

$targetHosts = @()

switch ($PSCmdlet.ParameterSetName) {
    'ByHosts' {
        Write-NPInfo "Target mode: explicit host list ($($Hosts.Count) host(s))."
        $targetHosts = $Hosts
    }
    'BySubnet' {
        Write-NPInfo "Target mode: subnet expansion for '$Subnet'."
        try {
            $targetHosts = Expand-NetworkPointerSubnet -Subnet $Subnet
            Write-NPInfo "Subnet expanded to $($targetHosts.Count) host address(es)."
        }
        catch {
            Write-NPError "Subnet expansion failed: $_"
            exit 1
        }
    }
}

if ($targetHosts.Count -eq 0) {
    Write-NPError 'No target hosts resolved. Aborting.'
    exit 1
}

Write-NPInfo "Ports to scan  : $($Ports -join ', ')"
Write-NPInfo "Ping timeout   : ${PingTimeout}ms"
Write-NPInfo "Port timeout   : ${PortTimeout}ms"
Write-NPInfo "Parallel mode  : $($Parallel.IsPresent)"
if ($Parallel) {
    Write-NPInfo "Throttle limit : $ThrottleLimit threads"
}
Write-NPInfo "Scan started   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host   '  ---------------------------------------------------------' -ForegroundColor DarkGray

$scanStart = Get-Date

$allResults = Invoke-NetworkPointerScan `
    -TargetHosts   $targetHosts `
    -Ports         $Ports `
    -PingTimeoutMs $PingTimeout `
    -PortTimeoutMs $PortTimeout `
    -RunParallel   $Parallel.IsPresent `
    -ThrottleLimit $ThrottleLimit

$scanEnd      = Get-Date
$scanDuration = ($scanEnd - $scanStart).TotalSeconds

Write-Host '  --------------------------------------------------------------' -ForegroundColor DarkGray

$filteredResults = Select-NetworkPointerResults `
    -Results       $allResults `
    -OnlineOnly:   $OnlineOnly `
    -OpenPortsOnly:$OpenPortsOnly

Write-Host ''
Write-Host '  SCAN RESULTS' -ForegroundColor Yellow
Write-Host '  --------------------------------------------------------------' -ForegroundColor DarkGray

if ($filteredResults.Count -eq 0) {
    Write-NPWarning 'No hosts matched the active filters.'
}
else {
    $sorted = $filteredResults | Sort-Object -Property @{Expression = 'PingOnline'; Descending = $true}, 'Host'
    foreach ($r in $sorted) {
        Write-NPHostResult -Result $r
    }
}

Write-Host ''
Write-Host '  ---------------------------------------------------------------' -ForegroundColor DarkGray
$onlineCount  = ($allResults | Where-Object PingOnline).Count
$offlineCount = $allResults.Count - $onlineCount
$openCount    = ($allResults | Where-Object { $_.OpenPortCount -gt 0 }).Count

Write-Host "  Total scanned    : $($allResults.Count) hosts" -ForegroundColor White
Write-Host "  Online           : $onlineCount" -ForegroundColor Green
Write-Host "  Offline          : $offlineCount" -ForegroundColor Red
Write-Host "  Hosts w/ open ports: $openCount" -ForegroundColor Yellow
Write-Host ("  Scan duration    : {0:N2} seconds" -f $scanDuration) -ForegroundColor White
Write-Host ''

if ($OutputCSV) {
    Export-NetworkPointerCSV -Results $filteredResults -Path $OutputCSV
}

if ($OutputHTML) {
    $title = if ($PSCmdlet.ParameterSetName -eq 'BySubnet') {
        "NetworkPointer — Subnet: $Subnet"
    } else {
        "NetworkPointer — Host Scan"
    }
    Export-NetworkPointerHTML -Results $filteredResults -Path $OutputHTML -ScanTitle $title
}

if (-not $OutputCSV -and -not $OutputHTML) {
    Write-NPInfo "Tip: Use -OutputCSV or -OutputHTML to save a report."
}

Write-NPInfo "Scan complete."
Write-Host ''
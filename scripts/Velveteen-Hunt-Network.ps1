<#
============================================================
VELVETEEN HUNT PACK
============================================================

MODULE: Network Hunt
PHASE: 03
MODE: NON-DESTRUCTIVE

=== PURPOSE ===

Hunt live network activity and process-linked traffic to surface suspicious
outbound behavior, possible beaconing patterns, unexpected listeners,
and control-surface context such as firewall, proxy, and hosts state.

Results may include broad context.
Do not ignore small or unusual findings.
Small signals may become critical when correlated later.

---

=== HOW TO RUN ===

1. Open PowerShell as Administrator
2. Copy and paste this script into the console

DO NOT:
- Save or execute this as a .ps1 file on a potentially compromised system
- Reuse scripts stored on the analyzed system
- Execute unknown scripts from the system under investigation

BEST PRACTICE — TRUSTED EXECUTION:

- Always source scripts from a trusted location:
  (secure GitHub repo, external USB, or known-safe machine)

- Treat the analyzed system as UNTRUSTED

- Prefer to:
  - review scripts on a separate clean machine
  - transfer only what is needed to the target system

- If risk is high:
  - execute scripts from read-only media (USB)
  - avoid leaving tools behind on the system

---

HIGH-RISK ENVIRONMENTS (IF COMPROMISE IS LIKELY):

- Minimize interaction with the live system
- Do NOT introduce unnecessary tools or files
- Prioritize evidence preservation over continued probing
- Consider disconnecting from the network if safe
- Prepare for disk imaging before further action

---

=== WHAT TO LOOK FOR ===

- Suspicious path + live external connection
- Elevated or SYSTEM processes communicating externally
- Unexpected listeners, unusual ports, or repeated remote endpoints
- LOLBins with network activity
- Proxy, hosts, or firewall conditions that change how traffic behaves

Focus on anomalies, not volume.

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# CONFIG
# =========================
$ModuleName = "Network Hunt"
$PhaseNumber = "03"
$ScriptName = "Velveteen-Hunt-Network"
$ReasonLine = "Live network hunt for process-linked traffic, possible C2 behavior, listeners, and control-surface context."

$FollowUpScripts = @(
    "Velveteen-Hunt-Correlation.ps1",
    "Velveteen-FollowUp-ProcessTrace.ps1",
    "Velveteen-FollowUp-FileTrace.ps1",
    "Velveteen-Hunt-Persistence.ps1"
)

$OutputRoot = Join-Path $env:USERPROFILE "Desktop\Velveteen-Hunt-Pack-Reports"
$AutoOpenReport = $true
$CaseId = "<case-id>"
$AnalystInitials = "<initials>"

$CommonPorts = @(20,21,22,25,53,67,68,80,110,123,135,137,138,139,143,161,389,443,445,465,587,636,993,995,1433,1521,3306,3389,5432,5900,8080,8443)

# =========================
# HELPERS
# =========================
function Add-Line { param($Lines,[string]$Text) [void]$Lines.Add($Text) }
function Add-Blank { param($Lines) [void]$Lines.Add("") }
function Add-Header {
    param($Lines,[string]$Title)
    Add-Blank $Lines
    Add-Line $Lines ("=" * 68)
    Add-Line $Lines $Title
    Add-Line $Lines ("=" * 68)
}
function Safe-String { param($Value) if ($null -eq $Value) { "" } else { [string]$Value } }

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function New-SystemEvidenceId {
    "SYS-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMddHHmmss')"
}

function Test-SuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.Trim('"').ToLowerInvariant()
    return (
        $p -like "*\appdata\*"      -or
        $p -like "*\temp\*"         -or
        $p -like "*\programdata\*"  -or
        $p -like "*\downloads\*"    -or
        $p -like "*\desktop\*"      -or
        $p -like "*\users\public\*" -or
        $p -like "*\recycle.bin\*"
    )
}

function Test-IsLolbin {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $Name.ToLowerInvariant() -in @(
        "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
        "mshta.exe","rundll32.exe","regsvr32.exe"
    )
}

function Get-OwnerString {
    param($ProcessCim)
    try {
        $owner = Invoke-CimMethod -InputObject $ProcessCim -MethodName GetOwner -ErrorAction Stop
        if ($owner.ReturnValue -eq 0) {
            return "{0}\{1}" -f $owner.Domain, $owner.User
        }
    } catch {}
    "Unknown"
}

function Get-PrivilegeLabel {
    param([string]$Owner)
    if ([string]::IsNullOrWhiteSpace($Owner)) { return "Unknown" }
    if ($Owner -match "SYSTEM") { return "SYSTEM" }
    if ($Owner -match "LOCAL SERVICE") { return "LOCAL SERVICE" }
    if ($Owner -match "NETWORK SERVICE") { return "NETWORK SERVICE" }
    if ($Owner -match "Administrator") { return "AdminLike" }
    "User/Unknown"
}

function Get-SignerStatus {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return "Missing"
    }
    try {
        [string](Get-AuthenticodeSignature -FilePath $Path).Status
    } catch {
        "Error"
    }
}

function Get-AddressScope {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return "Unknown" }

    $a = $Address.Trim().ToLowerInvariant()

    if ($a -in @("127.0.0.1","::1","localhost")) { return "Loopback" }
    if ($a -eq "0.0.0.0" -or $a -eq "::") { return "Wildcard" }

    if ($a -match '^10\.') { return "Private" }
    if ($a -match '^192\.168\.') { return "Private" }
    if ($a -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return "Private" }
    if ($a -match '^169\.254\.') { return "LinkLocal" }

    if ($a -match '^fc' -or $a -match '^fd') { return "PrivateIPv6" }
    if ($a -match '^fe80:') { return "LinkLocalIPv6" }

    "External"
}

function Get-PortClass {
    param([int]$Port)

    if ($Port -eq 0) { return "None" }
    if ($CommonPorts -contains $Port) { return "Common" }
    if ($Port -ge 49152) { return "Ephemeral/High" }
    "LessCommon"
}

function New-Finding {
    param(
        [string]$Priority,
        [string]$Category,
        [string]$ObjectName,
        [string]$Finding,
        [string]$Why,
        [string]$Path = "",
        [string]$Extra = ""
    )
    [PSCustomObject]@{
        Priority = $Priority
        Category = $Category
        Object   = $ObjectName
        Path     = $Path
        Extra    = $Extra
        Finding  = $Finding
        Why      = $Why
    }
}

function Add-Finding {
    param($Bucket,$Finding)
    [void]$Bucket.Add($Finding)
}

function Write-Bucket {
    param($Lines,[string]$Title,$Bucket)
    Add-Header $Lines $Title
    if ($Bucket.Count -eq 0) {
        Add-Line $Lines "No items in this bucket."
        return
    }
    foreach ($Item in $Bucket) {
        Add-Line $Lines ("Review Priority: {0}" -f $Item.Priority)
        Add-Line $Lines ("Category: {0}" -f $Item.Category)
        Add-Line $Lines ("Object: {0}" -f $Item.Object)
        if ($Item.Path)  { Add-Line $Lines ("Path: {0}" -f $Item.Path) }
        if ($Item.Extra) { Add-Line $Lines ("Extra: {0}" -f $Item.Extra) }
        Add-Line $Lines ("Finding: {0}" -f $Item.Finding)
        Add-Line $Lines ("Why: {0}" -f $Item.Why)
        Add-Blank $Lines
    }
}

function Open-Report {
    param([string]$Path)
    try { Start-Process notepad.exe -ArgumentList "`"$Path`"" }
    catch { try { Invoke-Item -LiteralPath $Path } catch {} }
}

function Get-ProcessSnapshot {
    $rows = @()
    try {
        $procs = @(Get-CimInstance Win32_Process)
        foreach ($p in $procs) {
            $owner = Get-OwnerString $p
            $rows += [PSCustomObject]@{
                ProcessIdText  = [string]$p.ProcessId
                Name           = Safe-String $p.Name
                ExecutablePath = (Safe-String $p.ExecutablePath).Trim('"')
                CommandLine    = Safe-String $p.CommandLine
                Owner          = $owner
                Privilege      = Get-PrivilegeLabel $owner
            }
        }
    } catch {}
    $rows
}

function Get-ProxyState {
    try {
        $proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $item = Get-ItemProperty -Path $proxyKey -ErrorAction Stop
        [PSCustomObject]@{
            ProxyEnable   = Safe-String $item.ProxyEnable
            ProxyServer   = Safe-String $item.ProxyServer
            AutoConfigURL = Safe-String $item.AutoConfigURL
        }
    } catch {
        [PSCustomObject]@{
            ProxyEnable   = "Unknown"
            ProxyServer   = ""
            AutoConfigURL = ""
        }
    }
}

function Get-HostsSummary {
    $hostsPath = Join-Path $env:WINDIR "System32\drivers\etc\hosts"
    $hash = "Unavailable"
    $nonCommentCount = 0

    if (Test-Path -LiteralPath $hostsPath) {
        try { $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $hostsPath).Hash } catch {}
        try {
            $lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop
            $nonCommentCount = @($lines | Where-Object {
                $_.Trim() -and -not $_.Trim().StartsWith("#")
            }).Count
        } catch {}
    }

    [PSCustomObject]@{
        Path = $hostsPath
        Hash = $hash
        NonCommentCount = $nonCommentCount
    }
}

function Get-FirewallSummary {
    $summary = [PSCustomObject]@{
        TotalRules = 0
        EnabledInboundAllow = 0
        BroadRules = 0
        SampleBroad = @()
    }

    try {
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
        $summary.TotalRules = $rules.Count

        foreach ($r in $rules) {
            if ($r.Enabled -eq "True" -and $r.Direction -eq "Inbound" -and $r.Action -eq "Allow") {
                $summary.EnabledInboundAllow++
            }

            if ($r.Enabled -eq "True" -and $r.Action -eq "Allow") {
                $isBroad = $false
                try {
                    $addr = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
                    foreach ($a in $addr) {
                        if ((Safe-String $a.RemoteAddress) -match 'Any') { $isBroad = $true }
                    }
                } catch {}
                try {
                    $port = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop)
                    foreach ($p in $port) {
                        if ((Safe-String $p.LocalPort) -match 'Any') { $isBroad = $true }
                    }
                } catch {}

                if ($isBroad) {
                    $summary.BroadRules++
                    if ($summary.SampleBroad.Count -lt 5) {
                        $summary.SampleBroad += $r.DisplayName
                    }
                }
            }
        }
    } catch {}

    $summary
}

# =========================
# PREP
# =========================
Ensure-Directory $OutputRoot

$TimestampTag = Get-Date -Format "yyyy-MM-dd_HHmmss"
$SystemEvidenceId = New-SystemEvidenceId
$HostName = $env:COMPUTERNAME
$CreatedOn = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ReportPath = Join-Path $OutputRoot ("{0}_{1}.txt" -f $ScriptName, $TimestampTag)

$Lines = New-Object 'System.Collections.Generic.List[string]'
$HighPriority = New-Object 'System.Collections.Generic.List[object]'
$MediumPriority = New-Object 'System.Collections.Generic.List[object]'
$LowContext = New-Object 'System.Collections.Generic.List[object]'

# =========================
# COLLECTION
# =========================
$Processes = Get-ProcessSnapshot
$ProcessById = @{}
foreach ($p in $Processes) { $ProcessById[$p.ProcessIdText] = $p }

$Connections = @()
try {
    $Connections = @(Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess)
} catch {}

$GroupedConnections = @{}
$RemoteEndpointCounts = @{}
$ProcessConnectionCounts = @{}
$ListeningRows = @()

foreach ($c in $Connections) {
    $procId = [string]$c.OwningProcess
    $procName = "Unknown"
    $procPath = ""
    $procOwner = "Unknown"
    $procPriv = "Unknown"
    $signer = "Unknown"

    if ($ProcessById.ContainsKey($procId)) {
        $procName = $ProcessById[$procId].Name
        $procPath = $ProcessById[$procId].ExecutablePath
        $procOwner = $ProcessById[$procId].Owner
        $procPriv = $ProcessById[$procId].Privilege
        $signer = Get-SignerStatus $procPath
    }

    $remoteScope = Get-AddressScope $c.RemoteAddress
    $localScope = Get-AddressScope $c.LocalAddress
    $remotePortClass = Get-PortClass ([int]$c.RemotePort)
    $localPortClass = Get-PortClass ([int]$c.LocalPort)

    $groupKey = "{0}|{1}|{2}|{3}|{4}|{5}" -f $procId, $procName, $c.RemoteAddress, $c.RemotePort, $remoteScope, $c.State
    if (-not $GroupedConnections.ContainsKey($groupKey)) {
        $GroupedConnections[$groupKey] = [PSCustomObject]@{
            ProcId = $procId
            ProcName = $procName
            ProcPath = $procPath
            Owner = $procOwner
            Privilege = $procPriv
            Signer = $signer
            RemoteAddress = Safe-String $c.RemoteAddress
            RemotePort = [int]$c.RemotePort
            RemoteScope = $remoteScope
            RemotePortClass = $remotePortClass
            LocalAddress = Safe-String $c.LocalAddress
            LocalScope = $localScope
            States = New-Object 'System.Collections.Generic.HashSet[string]'
            LocalPorts = New-Object 'System.Collections.Generic.HashSet[string]'
            SeenCount = 0
        }
    }

    $GroupedConnections[$groupKey].SeenCount++
    [void]$GroupedConnections[$groupKey].States.Add((Safe-String $c.State))
    [void]$GroupedConnections[$groupKey].LocalPorts.Add((Safe-String $c.LocalPort))

    $endpointKey = "{0}:{1}" -f $c.RemoteAddress, $c.RemotePort
    if (-not $RemoteEndpointCounts.ContainsKey($endpointKey)) { $RemoteEndpointCounts[$endpointKey] = 0 }
    $RemoteEndpointCounts[$endpointKey]++

    if (-not $ProcessConnectionCounts.ContainsKey($procId)) {
        $ProcessConnectionCounts[$procId] = [PSCustomObject]@{
            ProcName = $procName
            ProcPath = $procPath
            Count = 0
        }
    }
    $ProcessConnectionCounts[$procId].Count++

    if ($c.State -eq "Listen") {
        $ListeningRows += [PSCustomObject]@{
            ProcId = $procId
            ProcName = $procName
            ProcPath = $procPath
            Owner = $procOwner
            Privilege = $procPriv
            Signer = $signer
            LocalAddress = Safe-String $c.LocalAddress
            LocalPort = [int]$c.LocalPort
            LocalScope = $localScope
            LocalPortClass = $localPortClass
        }
    }
}

$FirewallSummary = Get-FirewallSummary
$ProxyState = Get-ProxyState
$HostsSummary = Get-HostsSummary

# =========================
# FINDINGS
# =========================
foreach ($key in $GroupedConnections.Keys) {
    $item = $GroupedConnections[$key]

    $hasSuspiciousPath = Test-SuspiciousPath $item.ProcPath
    $isElevated = $item.Privilege -in @("SYSTEM","AdminLike","LOCAL SERVICE","NETWORK SERVICE")
    $isExternal = $item.RemoteScope -eq "External"
    $isLolbin = Test-IsLolbin $item.ProcName
    $isUnsigned = $item.Signer -in @("NotSigned","UnknownError","HashMismatch","Error")
    $hasRepeated = $item.SeenCount -ge 5
    $isLessCommonPort = $item.RemotePortClass -notin @("Common","None")
    $stateText = (($item.States | Sort-Object) -join ",")
    $localPortsText = (($item.LocalPorts | Sort-Object) -join ",")

    $priority = "LOW"

    if (($hasSuspiciousPath -and $isExternal -and $hasRepeated) -or
        ($hasSuspiciousPath -and $isElevated -and $isExternal) -or
        ($isUnsigned -and $isExternal -and $hasRepeated) -or
        ($isLolbin -and $isExternal)) {
        $priority = "HIGH"
    }
    elseif (($hasSuspiciousPath -and $isExternal) -or
            ($isElevated -and $isExternal) -or
            ($isUnsigned -and $isExternal) -or
            ($isLessCommonPort -and $isExternal) -or
            ($hasRepeated -and $isExternal) -or
            ($isLolbin -and $item.SeenCount -ge 1)) {
        $priority = "MEDIUM"
    }

    $finding = New-Finding $priority "Process-Linked Connection" ("{0} (PID {1})" -f $item.ProcName, $item.ProcId) `
        "Live process-linked network activity was observed." `
        "This preserves raw connection context and becomes more important when paired with suspicious path, privilege, signer, port, or repetition signals." `
        $item.ProcPath `
        ("ObservedCount={0}; StatesSeen={1}; Remote={2}:{3}; RemoteScope={4}; RemotePortClass={5}; LocalPortsSeen={6}; Privilege={7}; Owner={8}; Signer={9}" -f `
            $item.SeenCount, $stateText, $item.RemoteAddress, $item.RemotePort, $item.RemoteScope, $item.RemotePortClass, $localPortsText, $item.Privilege, $item.Owner, $item.Signer)

    if     ($priority -eq "HIGH")   { Add-Finding $HighPriority $finding }
    elseif ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding }
    else                            { Add-Finding $LowContext $finding }
}

foreach ($row in $ListeningRows) {
    $hasSuspiciousPath = Test-SuspiciousPath $row.ProcPath
    $isElevated = $row.Privilege -in @("SYSTEM","AdminLike","LOCAL SERVICE","NETWORK SERVICE")
    $isUnsigned = $row.Signer -in @("NotSigned","UnknownError","HashMismatch","Error")
    $isUncommonPort = $row.LocalPortClass -notin @("Common","None")

    $priority = "LOW"
    if (($hasSuspiciousPath -and ($isUncommonPort -or $isUnsigned)) -or
        ($hasSuspiciousPath -and $isElevated)) {
        $priority = "HIGH"
    }
    elseif ($hasSuspiciousPath -or $isUncommonPort -or $isUnsigned) {
        $priority = "MEDIUM"
    }

    $finding = New-Finding $priority "Listening Port" ("{0} (PID {1})" -f $row.ProcName, $row.ProcId) `
        "A listening socket was observed." `
        "Listeners are important because they may expose services, relays, backdoors, or local proxy behavior. Context matters." `
        $row.ProcPath `
        ("Listen={0}:{1}; LocalScope={2}; LocalPortClass={3}; Privilege={4}; Owner={5}; Signer={6}" -f `
            $row.LocalAddress, $row.LocalPort, $row.LocalScope, $row.LocalPortClass, $row.Privilege, $row.Owner, $row.Signer)

    if     ($priority -eq "HIGH")   { Add-Finding $HighPriority $finding }
    elseif ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding }
    else                            { Add-Finding $LowContext $finding }
}

# Loopback / local proxy style hints
foreach ($key in $GroupedConnections.Keys) {
    $item = $GroupedConnections[$key]
    if ($item.RemoteScope -eq "Loopback" -and $item.SeenCount -ge 3) {
        $finding = New-Finding "MEDIUM" "Loopback / Proxy Pattern" ("{0} (PID {1})" -f $item.ProcName, $item.ProcId) `
            "Repeated loopback connection activity was observed." `
            "Repeated loopback traffic can be normal, but it can also indicate relays, local proxies, or tunneled application behavior worth correlating." `
            $item.ProcPath `
            ("ObservedCount={0}; Remote={1}:{2}; LocalPortsSeen={3}; Privilege={4}; Owner={5}" -f `
                $item.SeenCount, $item.RemoteAddress, $item.RemotePort, (($item.LocalPorts | Sort-Object) -join ","), $item.Privilege, $item.Owner)
        Add-Finding $MediumPriority $finding
    }
}

# Remote endpoint repetition
foreach ($endpoint in $RemoteEndpointCounts.Keys) {
    if ($RemoteEndpointCounts[$endpoint] -ge 5) {
        $finding = New-Finding "MEDIUM" "Repeated Remote Endpoint" $endpoint `
            "A remote endpoint was contacted repeatedly." `
            "Repeated hits to the same endpoint can be normal for web apps, but they may also support callback or beacon-style patterns depending on owning process context." `
            "" `
            ("ObservedCount={0}" -f $RemoteEndpointCounts[$endpoint])
        Add-Finding $MediumPriority $finding
    }
}

# Top talkers summary entries
$TopTalkers = @($ProcessConnectionCounts.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | Select-Object -First 5)
foreach ($entry in $TopTalkers) {
    $procId = $entry.Key
    $info = $entry.Value
    $priority = if (Test-SuspiciousPath $info.ProcPath) { "MEDIUM" } else { "LOW" }

    $finding = New-Finding $priority "Top Talker" ("{0} (PID {1})" -f $info.ProcName, $procId) `
        "This process appeared among the most connection-active processes in the snapshot." `
        "High connection volume is not malicious by itself, but it is useful context for prioritizing network review." `
        $info.ProcPath `
        ("ConnectionCount={0}" -f $info.Count)

    if ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding } else { Add-Finding $LowContext $finding }
}

# Firewall summary
if ($FirewallSummary.BroadRules -gt 0) {
    Add-Finding $MediumPriority (New-Finding "MEDIUM" "Firewall Summary" "Broad Allow Rules" `
        "Broad enabled allow rules were observed in the active firewall policy." `
        "Broad allow rules can weaken controls and may be relevant when correlating unexpected listeners or outbound traffic." `
        "" `
        ("TotalRules={0}; EnabledInboundAllow={1}; BroadAllowRules={2}; Sample={3}" -f `
            $FirewallSummary.TotalRules, $FirewallSummary.EnabledInboundAllow, $FirewallSummary.BroadRules, ($FirewallSummary.SampleBroad -join " | ")))
}
else {
    Add-Finding $LowContext (New-Finding "LOW" "Firewall Summary" "Active Firewall Policy" `
        "Firewall summary was captured." `
        "This provides environment context for later review." `
        "" `
        ("TotalRules={0}; EnabledInboundAllow={1}; BroadAllowRules={2}" -f `
            $FirewallSummary.TotalRules, $FirewallSummary.EnabledInboundAllow, $FirewallSummary.BroadRules))
}

# Proxy summary
if (($ProxyState.ProxyEnable -eq "1") -or $ProxyState.ProxyServer -or $ProxyState.AutoConfigURL) {
    Add-Finding $MediumPriority (New-Finding "MEDIUM" "Proxy Summary" "Internet Settings Proxy" `
        "Proxy-related settings are enabled or populated." `
        "Proxy configuration can materially affect how traffic appears and may be relevant when reviewing network routes or suspicious connectivity." `
        "" `
        ("ProxyEnable={0}; ProxyServer={1}; AutoConfigURL={2}" -f $ProxyState.ProxyEnable, $ProxyState.ProxyServer, $ProxyState.AutoConfigURL))
}
else {
    Add-Finding $LowContext (New-Finding "LOW" "Proxy Summary" "Internet Settings Proxy" `
        "Proxy-related settings were captured." `
        "This provides environment context for later review." `
        "" `
        ("ProxyEnable={0}; ProxyServer={1}; AutoConfigURL={2}" -f $ProxyState.ProxyEnable, $ProxyState.ProxyServer, $ProxyState.AutoConfigURL))
}

# Hosts summary
if ($HostsSummary.NonCommentCount -gt 0) {
    Add-Finding $MediumPriority (New-Finding "MEDIUM" "Hosts Summary" "hosts" `
        "Non-comment hosts entries were present." `
        "Hosts entries can affect local resolution and should be reviewed in context with suspicious traffic or redirection concerns." `
        $HostsSummary.Path `
        ("NonCommentEntries={0}; SHA256={1}" -f $HostsSummary.NonCommentCount, $HostsSummary.Hash))
}
else {
    Add-Finding $LowContext (New-Finding "LOW" "Hosts Summary" "hosts" `
        "Hosts file summary was captured." `
        "This provides environment context for later review." `
        $HostsSummary.Path `
        ("NonCommentEntries={0}; SHA256={1}" -f $HostsSummary.NonCommentCount, $HostsSummary.Hash))
}

# =========================
# REPORT BODY
# =========================
$CollectedAt = Get-Date
$ObservationDensity = [math]::Round((($HighPriority.Count + $MediumPriority.Count + $LowContext.Count) / 1.0),2)

Add-Header $Lines "SUMMARY"
Add-Line $Lines ("Connections reviewed: {0}" -f $Connections.Count)
Add-Line $Lines ("Grouped connection patterns: {0}" -f $GroupedConnections.Count)
Add-Line $Lines ("Listeners observed: {0}" -f $ListeningRows.Count)
Add-Line $Lines ("High Priority Findings: {0}" -f $HighPriority.Count)
Add-Line $Lines ("Medium Priority Findings: {0}" -f $MediumPriority.Count)
Add-Line $Lines ("Low Context Findings: {0}" -f $LowContext.Count)
Add-Line $Lines ("Total Findings: {0}" -f ($HighPriority.Count + $MediumPriority.Count + $LowContext.Count))
Add-Line $Lines ("Observation Density: {0} findings / snapshot" -f $ObservationDensity)

Write-Bucket $Lines "HIGH PRIORITY" $HighPriority
Write-Bucket $Lines "MEDIUM PRIORITY" $MediumPriority
Write-Bucket $Lines "LOW CONTEXT" $LowContext

Add-Blank $Lines
Add-Line $Lines "This output is an evidence artifact."
Add-Line $Lines "No final conclusion is made at this stage."

Add-Header $Lines "BEHAVIORAL NARRATIVE"
if (($HighPriority.Count + $MediumPriority.Count + $LowContext.Count) -eq 0) {
    Add-Line $Lines "No notable network findings were surfaced in the current snapshot."
}
else {
    Add-Line $Lines "The snapshot captured live process-linked traffic, listener context, and control-surface environment details."
    Add-Line $Lines ("Grouped connection patterns observed: {0}" -f $GroupedConnections.Count)
    Add-Line $Lines ("Listener rows observed: {0}" -f $ListeningRows.Count)
    Add-Line $Lines ("Repeated remote endpoints above threshold: {0}" -f (@($RemoteEndpointCounts.Keys | Where-Object { $RemoteEndpointCounts[$_] -ge 5 }).Count))
    Add-Line $Lines "This narrative is organizational only and does not replace raw review of the grouped findings above."
}

Add-Header $Lines "WIRESHARK PIVOT NOTES"
Add-Line $Lines "Use these pivot ideas for deeper packet review:"
Add-Line $Lines "- ip.addr == <remote-ip>"
Add-Line $Lines "- tcp.port == <port>"
Add-Line $Lines "- ip.addr == <remote-ip> and tcp.port == <port>"
Add-Line $Lines "- Focus first on High Priority remote endpoints and unusual listeners."
Add-Line $Lines "- Compare repeated endpoints to the owning process path and signer state in this report."

Add-Header $Lines "ANALYST NOTES"
if (($HighPriority.Count + $MediumPriority.Count + $LowContext.Count) -gt 0) {
    Add-Line $Lines "- Raw network observations were preserved and grouped to reduce repeated line spam without dropping context."
    Add-Line $Lines "- Priority bucketing is intentionally light. Review combined red flags first."
    Add-Line $Lines "- Standard browser, svchost, or service traffic may still appear; use process path, privilege, signer, port class, and repetition together."
    Add-Line $Lines "- Correlate this output with LiveProcess, Sentinel, Persistence, and Correlation modules."
}
else {
    Add-Line $Lines "- No network findings surfaced from the current snapshot."
    Add-Line $Lines "- This does not prove the host is clean. Re-run during suspected activity or pivot to Sentinel / Correlation."
}

# =========================
# WRITE BODY
# =========================
$Lines | Set-Content -LiteralPath $ReportPath -Encoding UTF8
$FileSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ReportPath).Hash

$TopPriority = "LOW"
if ($HighPriority.Count -gt 0) { $TopPriority = "HIGH" }
elseif ($MediumPriority.Count -gt 0) { $TopPriority = "MEDIUM" }

# =========================
# FOOTER
# =========================
$Footer = New-Object 'System.Collections.Generic.List[string]'

Add-Blank $Footer
Add-Line $Footer "IMPORTANT NOTE:"
Add-Line $Footer "This output is automatically opened as a text file upon script completion."
Add-Line $Footer "This file is an evidence artifact and must be preserved immediately."
Add-Blank $Footer
Add-Line $Footer "---"
Add-Blank $Footer

Add-Line $Footer "=== IMPORTANT NEXT ACTIONS ==="
Add-Blank $Footer
Add-Line $Footer "1. Save this output immediately"
Add-Blank $Footer
Add-Line $Footer "2. Move this file and case folder to:"
Add-Line $Footer "   - Primary storage: external SSD"
Add-Line $Footer "   - Secondary storage: secure cloud backup (Google Drive / Dropbox)"
Add-Blank $Footer
Add-Line $Footer "3. Copy the Chain of Custody Entry below into:"
Add-Line $Footer "   00-admin/chain-of-custody.txt"
Add-Blank $Footer
Add-Line $Footer "4. Assign your official Evidence Number (EV-XXXX)"
Add-Blank $Footer
Add-Line $Footer "Do NOT leave this artifact stored only on the analyzed system."
Add-Blank $Footer
Add-Line $Footer "---"
Add-Blank $Footer

Add-Line $Footer "=== ANALYST SIGNATURE ==="
Add-Blank $Footer
Add-Line $Footer "Case ID: $CaseId"
Add-Line $Footer "System Evidence ID: $SystemEvidenceId"
Add-Line $Footer "Analyst Evidence No: (assign manually)"
Add-Line $Footer "Analyst Initials: $AnalystInitials"
Add-Line $Footer ("Timestamp (UTC): {0}" -f ([DateTime]::UtcNow).ToString("yyyy-MM-dd HH:mm:ss UTC"))
Add-Line $Footer "File SHA256: $FileSha256"
Add-Blank $Footer
Add-Line $Footer "Statement:"
Add-Line $Footer "I confirm this artifact reflects actions taken during this investigation."
Add-Blank $Footer
Add-Line $Footer "---"
Add-Blank $Footer

Add-Line $Footer "=== ARTIFACT METADATA ==="
Add-Blank $Footer
Add-Line $Footer "System Evidence ID: $SystemEvidenceId"
Add-Line $Footer "Module: $ModuleName"
Add-Line $Footer "Created By: $ScriptName"
Add-Line $Footer "Created On: $CreatedOn"
Add-Line $Footer "Host: $HostName"
Add-Line $Footer "Output File: $ReportPath"
Add-Blank $Footer
Add-Line $Footer "---"
Add-Blank $Footer

Add-Line $Footer "=== CHAIN OF CUSTODY ENTRY (COPY) ==="
Add-Blank $Footer
Add-Line $Footer ("[{0}]" -f ([DateTime]::UtcNow).ToString("yyyy-MM-dd HH:mm:ss UTC"))
Add-Line $Footer "Case ID: $CaseId"
Add-Line $Footer "System Evidence ID: $SystemEvidenceId"
Add-Line $Footer "Analyst Evidence No: (assign manually)"
Add-Line $Footer "Analyst: $AnalystInitials"
Add-Blank $Footer
Add-Line $Footer "Action: Generated module output"
Add-Line $Footer "Artifact: $ReportPath"
Add-Line $Footer "Reason: $ReasonLine"
Add-Blank $Footer
Add-Line $Footer "Hash Logged: Yes"
Add-Line $Footer "Seal Created: Yes"
Add-Blank $Footer
Add-Line $Footer "---"
Add-Blank $Footer

Add-Line $Footer "=== ESCALATION CHECK ==="
Add-Blank $Footer
Add-Line $Footer "If multiple indicators of compromise are present,"
Add-Line $Footer "consider disk imaging before continuing."
Add-Blank $Footer
Add-Line $Footer "Run:"
Add-Line $Footer "03-00-compromise-assessment-and-imaging-decision"
Add-Blank $Footer
Add-Line $Footer "---"
Add-Blank $Footer

Add-Line $Footer "REVIEW PRIORITY GUIDANCE"
Add-Blank $Footer
Add-Line $Footer "HIGH PRIORITY:"
Add-Line $Footer "- Obvious combined red flags or strong process-network anomalies"
Add-Blank $Footer
Add-Line $Footer "MEDIUM PRIORITY:"
Add-Line $Footer "- Worth focused review and correlation"
Add-Blank $Footer
Add-Line $Footer "LOW CONTEXT:"
Add-Line $Footer "- Contextual or supporting observations retained for later analysis"

if ($TopPriority -eq "HIGH" -and $HighPriority.Count -ge 2) {
    Add-Blank $Footer
    Add-Line $Footer "---"
    Add-Blank $Footer
    Add-Line $Footer "=== ESCALATION REQUIRED ==="
    Add-Blank $Footer
    Add-Line $Footer "Multiple high-priority network indicators were identified."
    Add-Blank $Footer
    Add-Line $Footer "Disk imaging should be considered before continuing investigation."
    Add-Blank $Footer
    Add-Line $Footer "Run immediately:"
    Add-Line $Footer "03-00-compromise-assessment-and-imaging-decision"
}

Add-Blank $Footer
Add-Line $Footer "=== FOLLOW-UP ==="
Add-Blank $Footer
foreach ($FollowUp in $FollowUpScripts) {
    Add-Line $Footer $FollowUp
}

Add-Content -LiteralPath $ReportPath -Value $Footer

# =========================
# AUTO OPEN
# =========================
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "VELVETEEN NETWORK HUNT COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Output File: $ReportPath"
Write-Host "System Evidence ID: $SystemEvidenceId"
Write-Host "Connections Reviewed: $($Connections.Count)"
Write-Host "Grouped Patterns: $($GroupedConnections.Count)"
Write-Host "Listeners: $($ListeningRows.Count)"
Write-Host "High Priority: $($HighPriority.Count)"
Write-Host "Medium Priority: $($MediumPriority.Count)"
Write-Host "Low Context: $($LowContext.Count)"
Write-Host "Total Findings: $(($HighPriority.Count + $MediumPriority.Count + $LowContext.Count))"
Write-Host "Top Priority: $TopPriority"
Write-Host "SHA256: $FileSha256"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if ($AutoOpenReport) {
    Open-Report $ReportPath
}

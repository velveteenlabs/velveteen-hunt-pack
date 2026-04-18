<#
============================================================
VELVETEEN HUNT PACK
============================================================

MODULE: Sentinel Watch
PHASE: 02
MODE: NON-DESTRUCTIVE

=== PURPOSE ===

Watch the live system for short-duration behavioral changes that static
review may miss, including process launches, repeated launches,
connection activity, file activity, persistence creation, and control changes.

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

- New suspicious processes, repeated respawns, or short-lived bursts involving script hosts, LOLBins, or odd paths
- New outbound connections, suspicious listening behavior, or repeated callback-style activity during the watch window
- New suspicious file drops, new persistence, or proxy/hosts/firewall changes during observation

Focus on anomalies, not volume.

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# CONFIG
# =========================
$ModuleName = "Sentinel Watch"
$PhaseNumber = "02"
$ScriptName = "Velveteen-Hunt-Sentinel"
$ReasonLine = "Short-duration live observation for suspicious process activity, connection changes, new drops, persistence, and control tampering."

$FollowUpScripts = @(
    "Velveteen-Hunt-Network.ps1",
    "Velveteen-Hunt-Persistence.ps1",
    "Velveteen-Hunt-Correlation.ps1",
    "Velveteen-FollowUp-ProcessTrace.ps1",
    "Velveteen-FollowUp-FileTrace.ps1"
)

$OutputRoot = Join-Path $env:USERPROFILE "Desktop\Velveteen-Hunt-Pack-Reports"
$AutoOpenReport = $true
$CaseId = "<case-id>"
$AnalystInitials = "<initials>"

$PollIntervalSeconds = 5
$OptionalMaxDurationSeconds = 0   # 0 = manual stop only

$WatchedExtensions = @(".exe",".dll",".ps1",".bat",".vbs",".js",".lnk",".sys",".dat",".log",".tmp",".cfg",".json",".ini")
$StrongExtensions  = @(".exe",".dll",".ps1",".bat",".vbs",".js",".lnk",".sys")

$WatchPaths = @(
    $env:TEMP,
    $env:APPDATA,
    $env:LOCALAPPDATA,
    $env:ProgramData,
    (Join-Path $env:USERPROFILE "Downloads"),
    (Join-Path $env:USERPROFILE "Desktop"),
    $env:PUBLIC
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

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
                ParentIdText   = [string]$p.ParentProcessId
                ExecutablePath = (Safe-String $p.ExecutablePath).Trim('"')
                CommandLine    = Safe-String $p.CommandLine
                Owner          = $owner
                Privilege      = Get-PrivilegeLabel $owner
            }
        }
    } catch {}
    $rows
}

function Get-ConnectionSnapshot {
    try {
        @(Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess)
    } catch {
        @()
    }
}

function Get-PerfSnapshot {
    $map = @{}
    try {
        $rows = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
            Where-Object { $_.IDProcess -ne 0 -and $_.Name -ne "_Total" -and $_.Name -ne "Idle" })
        foreach ($r in $rows) {
            $map[[string]$r.IDProcess] = [PSCustomObject]@{
                CPU = [double]$r.PercentProcessorTime
                WorkingSetMB = [math]::Round(([double]$r.WorkingSetPrivate / 1MB), 2)
            }
        }
    } catch {}
    $map
}

function Get-TaskSnapshot {
    $map = @{}
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            $key = "{0}\{1}" -f $t.TaskPath, $t.TaskName
            $map[$key] = [PSCustomObject]@{
                TaskName = $t.TaskName
                TaskPath = $t.TaskPath
                State    = Safe-String $t.State
            }
        }
    } catch {}
    $map
}

function Get-ServiceSnapshot {
    $map = @{}
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $map[$s.Name] = [PSCustomObject]@{
                Name        = $s.Name
                DisplayName = Safe-String $s.DisplayName
                State       = Safe-String $s.State
                StartMode   = Safe-String $s.StartMode
                PathName    = (Safe-String $s.PathName).Trim('"')
            }
        }
    } catch {}
    $map
}

function Get-FirewallSnapshot {
    $map = @{}
    try {
        foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)) {
            $map[$r.Name] = [PSCustomObject]@{
                Name        = $r.Name
                DisplayName = Safe-String $r.DisplayName
                Enabled     = Safe-String $r.Enabled
                Direction   = Safe-String $r.Direction
                Action      = Safe-String $r.Action
            }
        }
    } catch {}
    $map
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

function Get-HostsFileHash {
    $hostsPath = Join-Path $env:WINDIR "System32\drivers\etc\hosts"
    if (Test-Path -LiteralPath $hostsPath) {
        try { return (Get-FileHash -Algorithm SHA256 -LiteralPath $hostsPath).Hash } catch {}
    }
    "Unavailable"
}

function Get-RunKeySnapshot {
    $map = @{}
    $targets = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($path in $targets) {
        try {
            $item = Get-ItemProperty -Path $path -ErrorAction Stop
            foreach ($prop in $item.PSObject.Properties) {
                if ($prop.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                    $key = "{0}|{1}" -f $path, $prop.Name
                    $map[$key] = [PSCustomObject]@{
                        RegistryPath = $path
                        Name = $prop.Name
                        Value = Safe-String $prop.Value
                    }
                }
            }
        } catch {}
    }
    $map
}

function Get-StartupFolderSnapshot {
    $map = @{}
    $folders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($folder in $folders) {
        if (Test-Path -LiteralPath $folder) {
            try {
                foreach ($item in @(Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue)) {
                    $map[$item.FullName] = [PSCustomObject]@{
                        FullName = $item.FullName
                        Name = $item.Name
                        CreationTime = $item.CreationTime
                        LastWriteTime = $item.LastWriteTime
                    }
                }
            } catch {}
        }
    }
    $map
}

function Get-RecentFilesSnapshot {
    param([string[]]$Paths,[string[]]$Extensions,[datetime]$SinceTime)
    $results = @()
    foreach ($path in $Paths) {
        try {
            $files = Get-ChildItem -LiteralPath $path -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Extension -and
                    ($Extensions -contains $_.Extension.ToLowerInvariant()) -and
                    ($_.CreationTime -ge $SinceTime -or $_.LastWriteTime -ge $SinceTime)
                } |
                Select-Object FullName, Extension, CreationTime, LastWriteTime
            $results += $files
        } catch {}
    }
    $results
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

$GroupedProcesses   = @{}
$GroupedConnections = @{}
$GroupedFiles       = @{}
$GroupedCpuBursts   = @{}
$GroupedMemBursts   = @{}

# =========================
# BASELINES
# =========================
$WatchStarted = Get-Date
$StopRequested = $false
$StopMethod = "Operator pressed Q"

$BaselineProcesses = Get-ProcessSnapshot
$BaselineProcessIds = @{}
foreach ($row in $BaselineProcesses) { $BaselineProcessIds[$row.ProcessIdText] = $row }

$BaselineConnections = Get-ConnectionSnapshot
$BaselineConnKeys = @{}
foreach ($c in $BaselineConnections) {
    $key = "{0}|{1}|{2}|{3}|{4}|{5}" -f $c.OwningProcess, $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State
    $BaselineConnKeys[$key] = $true
}

$BaselineTasks = Get-TaskSnapshot
$BaselineServices = Get-ServiceSnapshot
$BaselineFirewall = Get-FirewallSnapshot
$BaselineProxy = Get-ProxyState
$BaselineHostsHash = Get-HostsFileHash
$BaselineRunKeys = Get-RunKeySnapshot
$BaselineStartupItems = Get-StartupFolderSnapshot

Write-Host ""
Write-Host "Sentinel running..." -ForegroundColor Cyan
Write-Host "Press Q to stop and generate report." -ForegroundColor Cyan
if ($OptionalMaxDurationSeconds -gt 0) {
    Write-Host "Maximum runtime: $OptionalMaxDurationSeconds seconds" -ForegroundColor Cyan
}
Write-Host ""

# =========================
# WATCH LOOP
# =========================
while (-not $StopRequested) {
    $Elapsed = (Get-Date) - $WatchStarted
    $TimerText = "{0:mm\:ss}" -f $Elapsed
    Write-Host "`rTimer: $TimerText | Watching... Press Q to stop and generate report. " -NoNewline -ForegroundColor Cyan

    $LoopStarted = Get-Date
    while (((Get-Date) - $LoopStarted).TotalSeconds -lt $PollIntervalSeconds) {
        Start-Sleep -Milliseconds 200

        if ([Console]::KeyAvailable) {
            $KeyPressed = [Console]::ReadKey($true)
            if ($KeyPressed.Key -eq 'Q') {
                $StopRequested = $true
                break
            }
        }

        if ($OptionalMaxDurationSeconds -gt 0) {
            $ElapsedNow = ((Get-Date) - $WatchStarted).TotalSeconds
            if ($ElapsedNow -ge $OptionalMaxDurationSeconds) {
                $StopRequested = $true
                $StopMethod = "Maximum runtime reached"
                break
            }
        }
    }

    if ($StopRequested) { break }

    $CurrentProcesses = Get-ProcessSnapshot
    $CurrentProcessIds = @{}
    foreach ($row in $CurrentProcesses) { $CurrentProcessIds[$row.ProcessIdText] = $row }

    foreach ($row in $CurrentProcesses) {
        if (-not $BaselineProcessIds.ContainsKey($row.ProcessIdText)) {
            $key = "{0}|{1}" -f $row.Name, $row.ExecutablePath
            if (-not $GroupedProcesses.ContainsKey($key)) {
                $GroupedProcesses[$key] = [PSCustomObject]@{
                    Name = $row.Name
                    Path = $row.ExecutablePath
                    Owner = $row.Owner
                    Privilege = $row.Privilege
                    SeenCount = 0
                    PidSet = New-Object 'System.Collections.Generic.HashSet[string]'
                    ParentSet = New-Object 'System.Collections.Generic.HashSet[string]'
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                }
            }
            $GroupedProcesses[$key].SeenCount++
            $GroupedProcesses[$key].LastSeen = Get-Date
            [void]$GroupedProcesses[$key].PidSet.Add($row.ProcessIdText)
            [void]$GroupedProcesses[$key].ParentSet.Add($row.ParentIdText)
        }
    }

    $CurrentConnections = Get-ConnectionSnapshot
    foreach ($conn in $CurrentConnections) {
        $connKey = "{0}|{1}|{2}|{3}|{4}|{5}" -f $conn.OwningProcess, $conn.LocalAddress, $conn.LocalPort, $conn.RemoteAddress, $conn.RemotePort, $conn.State
        if (-not $BaselineConnKeys.ContainsKey($connKey)) {
            $procId = [string]$conn.OwningProcess
            $procName = "Unknown"
            $procPath = ""
            $priv = "Unknown"
            $owner = "Unknown"

            if ($CurrentProcessIds.ContainsKey($procId)) {
                $procName = $CurrentProcessIds[$procId].Name
                $procPath = $CurrentProcessIds[$procId].ExecutablePath
                $priv = $CurrentProcessIds[$procId].Privilege
                $owner = $CurrentProcessIds[$procId].Owner
            }

            $key = "{0}|{1}|{2}|{3}|{4}" -f $procId, $procName, $conn.RemoteAddress, $conn.RemotePort, $conn.State
            if (-not $GroupedConnections.ContainsKey($key)) {
                $GroupedConnections[$key] = [PSCustomObject]@{
                    ProcName = $procName
                    ProcId = $procId
                    ProcPath = $procPath
                    Privilege = $priv
                    Owner = $owner
                    RemoteAddress = Safe-String $conn.RemoteAddress
                    RemotePort = Safe-String $conn.RemotePort
                    States = New-Object 'System.Collections.Generic.HashSet[string]'
                    LocalPorts = New-Object 'System.Collections.Generic.HashSet[string]'
                    SeenCount = 0
                    FirstSeen = Get-Date
                    LastSeen = Get-Date
                }
            }
            $GroupedConnections[$key].SeenCount++
            $GroupedConnections[$key].LastSeen = Get-Date
            [void]$GroupedConnections[$key].States.Add((Safe-String $conn.State))
            [void]$GroupedConnections[$key].LocalPorts.Add((Safe-String $conn.LocalPort))
        }
    }

    $RecentFiles = Get-RecentFilesSnapshot -Paths $WatchPaths -Extensions $WatchedExtensions -SinceTime $WatchStarted
    foreach ($file in $RecentFiles) {
        $eventType = if ($file.CreationTime -ge $WatchStarted) { "Created" } else { "Modified" }
        $key = "{0}|{1}" -f $file.FullName, $eventType
        if (-not $GroupedFiles.ContainsKey($key)) {
            $GroupedFiles[$key] = [PSCustomObject]@{
                Path = $file.FullName
                FileName = [IO.Path]::GetFileName($file.FullName)
                Extension = $file.Extension
                EventType = $eventType
                SeenCount = 0
                Created = $file.CreationTime
                FirstWrite = $file.LastWriteTime
                LastWrite = $file.LastWriteTime
            }
        }
        $GroupedFiles[$key].SeenCount++
        if ($file.LastWriteTime -lt $GroupedFiles[$key].FirstWrite) { $GroupedFiles[$key].FirstWrite = $file.LastWriteTime }
        if ($file.LastWriteTime -gt $GroupedFiles[$key].LastWrite)  { $GroupedFiles[$key].LastWrite = $file.LastWriteTime }
    }

    $CurrentTasks = Get-TaskSnapshot
    foreach ($taskKey in $CurrentTasks.Keys) {
        if (-not $BaselineTasks.ContainsKey($taskKey)) {
            $t = $CurrentTasks[$taskKey]
            Add-Finding $HighPriority (New-Finding "HIGH" "New Scheduled Task" $taskKey "New scheduled task observed during watch window." "Task creation during live observation is a strong persistence signal." "" ("State={0}" -f $t.State))
        }
    }

    $CurrentServices = Get-ServiceSnapshot
    foreach ($svcName in $CurrentServices.Keys) {
        if (-not $BaselineServices.ContainsKey($svcName)) {
            $s = $CurrentServices[$svcName]
            Add-Finding $HighPriority (New-Finding "HIGH" "New Service" $s.Name "New service observed during watch window." "Service creation during observation can indicate persistence or high-risk system change." $s.PathName ("DisplayName={0}; StartMode={1}; State={2}" -f $s.DisplayName, $s.StartMode, $s.State))
        }
    }

    $CurrentRunKeys = Get-RunKeySnapshot
    foreach ($rk in $CurrentRunKeys.Keys) {
        if (-not $BaselineRunKeys.ContainsKey($rk)) {
            $entry = $CurrentRunKeys[$rk]
            Add-Finding $HighPriority (New-Finding "HIGH" "New Run Key" $entry.Name "New Run / RunOnce registry persistence observed during watch window." "New autorun registry entries created during observation are a strong persistence signal." $entry.RegistryPath ("Value={0}" -f $entry.Value))
        }
    }

    $CurrentStartupItems = Get-StartupFolderSnapshot
    foreach ($sp in $CurrentStartupItems.Keys) {
        if (-not $BaselineStartupItems.ContainsKey($sp)) {
            $entry = $CurrentStartupItems[$sp]
            Add-Finding $HighPriority (New-Finding "HIGH" "New Startup Item" $entry.Name "New startup folder item observed during watch window." "New startup folder entries can indicate persistence or launcher staging." $entry.FullName ("Created={0}; LastWrite={1}" -f $entry.CreationTime, $entry.LastWriteTime))
        }
    }

    $CurrentFirewall = Get-FirewallSnapshot
    foreach ($ruleName in $CurrentFirewall.Keys) {
        if (-not $BaselineFirewall.ContainsKey($ruleName)) {
            $r = $CurrentFirewall[$ruleName]
            Add-Finding $MediumPriority (New-Finding "MEDIUM" "Firewall Change" $r.Name "New firewall rule observed during watch window." "Firewall rule changes can weaken controls or facilitate persistence / access." "" ("DisplayName={0}; Direction={1}; Action={2}; Enabled={3}" -f $r.DisplayName, $r.Direction, $r.Action, $r.Enabled))
        }
    }

    $CurrentProxy = Get-ProxyState
    if (
        $CurrentProxy.ProxyEnable -ne $BaselineProxy.ProxyEnable -or
        $CurrentProxy.ProxyServer -ne $BaselineProxy.ProxyServer -or
        $CurrentProxy.AutoConfigURL -ne $BaselineProxy.AutoConfigURL
    ) {
        Add-Finding $MediumPriority (New-Finding "MEDIUM" "Proxy Change" "Internet Settings Proxy" "Proxy configuration changed during watch window." "Proxy changes can redirect traffic or alter external communications." "" ("Before=Enable:{0};Server:{1};PAC:{2} | After=Enable:{3};Server:{4};PAC:{5}" -f $BaselineProxy.ProxyEnable, $BaselineProxy.ProxyServer, $BaselineProxy.AutoConfigURL, $CurrentProxy.ProxyEnable, $CurrentProxy.ProxyServer, $CurrentProxy.AutoConfigURL))
        $BaselineProxy = $CurrentProxy
    }

    $CurrentHostsHash = Get-HostsFileHash
    if ($CurrentHostsHash -ne $BaselineHostsHash) {
        Add-Finding $MediumPriority (New-Finding "MEDIUM" "Hosts File Change" "hosts" "Hosts file changed during watch window." "Hosts changes can redirect domains or alter command-and-control routing." (Join-Path $env:WINDIR "System32\drivers\etc\hosts") ("Before={0}; After={1}" -f $BaselineHostsHash, $CurrentHostsHash))
        $BaselineHostsHash = $CurrentHostsHash
    }

    $PerfMap = Get-PerfSnapshot
    foreach ($procId in $PerfMap.Keys) {
        $perf = $PerfMap[$procId]

        if ($perf.CPU -ge 25) {
            $name = "Unknown"; $path = ""
            if ($CurrentProcessIds.ContainsKey($procId)) {
                $name = $CurrentProcessIds[$procId].Name
                $path = $CurrentProcessIds[$procId].ExecutablePath
            }
            $key = "{0}|{1}" -f $name, $path
            if (-not $GroupedCpuBursts.ContainsKey($key)) {
                $GroupedCpuBursts[$key] = [PSCustomObject]@{
                    Name = $name
                    Path = $path
                    ObservedCount = 0
                    MaxCPU = 0
                }
            }
            $GroupedCpuBursts[$key].ObservedCount++
            if ($perf.CPU -gt $GroupedCpuBursts[$key].MaxCPU) { $GroupedCpuBursts[$key].MaxCPU = $perf.CPU }
        }

        if ($perf.WorkingSetMB -ge 500) {
            $name = "Unknown"; $path = ""
            if ($CurrentProcessIds.ContainsKey($procId)) {
                $name = $CurrentProcessIds[$procId].Name
                $path = $CurrentProcessIds[$procId].ExecutablePath
            }
            $key = "{0}|{1}" -f $name, $path
            if (-not $GroupedMemBursts.ContainsKey($key)) {
                $GroupedMemBursts[$key] = [PSCustomObject]@{
                    Name = $name
                    Path = $path
                    ObservedCount = 0
                    MaxWorkingSetMB = 0
                }
            }
            $GroupedMemBursts[$key].ObservedCount++
            if ($perf.WorkingSetMB -gt $GroupedMemBursts[$key].MaxWorkingSetMB) { $GroupedMemBursts[$key].MaxWorkingSetMB = $perf.WorkingSetMB }
        }
    }
}

Write-Host ""
Write-Host "Manual stop triggered. Finalizing report..." -ForegroundColor Yellow

# =========================
# GROUP RAW EVENTS INTO BUCKETS
# =========================
foreach ($key in $GroupedProcesses.Keys) {
    $item = $GroupedProcesses[$key]
    $isSuspiciousPath = Test-SuspiciousPath $item.Path
    $isLolbin = Test-IsLolbin $item.Name
    $isElevated = $item.Privilege -in @("SYSTEM","AdminLike","LOCAL SERVICE","NETWORK SERVICE")

    $priority = if (($isSuspiciousPath -and $isElevated) -or ($item.SeenCount -ge 3)) { "HIGH" }
                elseif ($isSuspiciousPath -or $isLolbin -or $isElevated) { "MEDIUM" }
                else { "LOW" }

    $finding = New-Finding $priority "New / Respawned Process" $item.Name `
        "New or repeated process activity was observed during the watch window." `
        "Repeated launches, respawns, or short-lived executions can indicate watchdog behavior, staged execution, or activity that static review may miss." `
        $item.Path `
        ("ObservedCount={0}; UniquePIDs={1}; ParentPIDs={2}; Owner={3}; Privilege={4}; FirstSeen={5}; LastSeen={6}" -f `
            $item.SeenCount, $item.PidSet.Count, (($item.ParentSet | Sort-Object) -join ","), $item.Owner, $item.Privilege, $item.FirstSeen, $item.LastSeen)

    if     ($priority -eq "HIGH")   { Add-Finding $HighPriority $finding }
    elseif ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding }
    else                            { Add-Finding $LowContext $finding }
}

foreach ($key in $GroupedConnections.Keys) {
    $item = $GroupedConnections[$key]
    $hasSuspiciousPath = Test-SuspiciousPath $item.ProcPath
    $isElevated = $item.Privilege -in @("SYSTEM","AdminLike","LOCAL SERVICE","NETWORK SERVICE")
    $priority = if ($hasSuspiciousPath -and ($item.SeenCount -ge 2 -or $isElevated)) { "HIGH" }
                elseif ($hasSuspiciousPath) { "MEDIUM" }
                else { "LOW" }

    $finding = New-Finding $priority "New Connection Activity" ("{0} (PID {1})" -f $item.ProcName, $item.ProcId) `
        "New process-linked connection activity was observed during the watch window." `
        "Connection activity is preserved here as grouped raw context. It becomes more important when paired with suspicious execution path, elevation, or other anomalies." `
        $item.ProcPath `
        ("ObservedCount={0}; StatesSeen={1}; Remote={2}:{3}; LocalPortsSeen={4}; Privilege={5}; Owner={6}; FirstSeen={7}; LastSeen={8}" -f `
            $item.SeenCount, (($item.States | Sort-Object) -join ","), $item.RemoteAddress, $item.RemotePort, (($item.LocalPorts | Sort-Object) -join ","), $item.Privilege, $item.Owner, $item.FirstSeen, $item.LastSeen)

    if     ($priority -eq "HIGH")   { Add-Finding $HighPriority $finding }
    elseif ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding }
    else                            { Add-Finding $LowContext $finding }
}

foreach ($key in $GroupedFiles.Keys) {
    $item = $GroupedFiles[$key]
    $isStrongType = $StrongExtensions -contains $item.Extension.ToLowerInvariant()
    $isSuspiciousPath = Test-SuspiciousPath $item.Path

    $priority = if ($isStrongType -and $isSuspiciousPath) { "HIGH" }
                elseif ($isStrongType -or $isSuspiciousPath) { "MEDIUM" }
                else { "LOW" }

    $finding = New-Finding $priority "File Activity" $item.FileName `
        "New or changed file activity was observed during the watch window." `
        "File activity is preserved here as grouped raw context. Executables, scripts, links, drivers, or strong path/context combinations deserve closer review." `
        $item.Path `
        ("EventType={0}; Extension={1}; ObservedCount={2}; Created={3}; FirstWrite={4}; LastWrite={5}" -f `
            $item.EventType, $item.Extension, $item.SeenCount, $item.Created, $item.FirstWrite, $item.LastWrite)

    if     ($priority -eq "HIGH")   { Add-Finding $HighPriority $finding }
    elseif ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding }
    else                            { Add-Finding $LowContext $finding }
}

foreach ($key in $GroupedCpuBursts.Keys) {
    $item = $GroupedCpuBursts[$key]
    $priority = if (Test-SuspiciousPath $item.Path) { "MEDIUM" } else { "LOW" }
    $finding = New-Finding $priority "CPU Burst" $item.Name `
        "Notable CPU burst activity was observed during the watch window." `
        "Short bursts of execution can align with staged activity, capture, scanning, or background task spikes. Raw context is preserved here for correlation." `
        $item.Path `
        ("ObservedCount={0}; MaxCPU={1}" -f $item.ObservedCount, $item.MaxCPU)
    if ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding } else { Add-Finding $LowContext $finding }
}

foreach ($key in $GroupedMemBursts.Keys) {
    $item = $GroupedMemBursts[$key]
    $priority = if (Test-SuspiciousPath $item.Path) { "MEDIUM" } else { "LOW" }
    $finding = New-Finding $priority "Memory Growth" $item.Name `
        "Notable memory growth was observed during the watch window." `
        "Memory growth can align with normal app behavior or suspicious staged activity. Raw context is preserved here for correlation." `
        $item.Path `
        ("ObservedCount={0}; MaxWorkingSetMB={1}" -f $item.ObservedCount, $item.MaxWorkingSetMB)
    if ($priority -eq "MEDIUM") { Add-Finding $MediumPriority $finding } else { Add-Finding $LowContext $finding }
}

# =========================
# REPORT BODY
# =========================
$ElapsedFinal = (Get-Date) - $WatchStarted
$ElapsedText = "{0:hh\:mm\:ss}" -f $ElapsedFinal

Add-Header $Lines "SUMMARY"
Add-Line $Lines ("Sentinel Mode: Manual stop")
Add-Line $Lines ("Elapsed Watch Time: {0}" -f $ElapsedText)
Add-Line $Lines ("Stop Method: {0}" -f $StopMethod)
Add-Line $Lines ("Poll interval (seconds): {0}" -f $PollIntervalSeconds)
Add-Line $Lines ("Watched paths: {0}" -f ($WatchPaths -join "; "))
Add-Line $Lines ("Grouped Process Events: {0}" -f $GroupedProcesses.Count)
Add-Line $Lines ("Grouped Connection Events: {0}" -f $GroupedConnections.Count)
Add-Line $Lines ("Grouped File Events: {0}" -f $GroupedFiles.Count)
Add-Line $Lines ("Grouped CPU Burst Events: {0}" -f $GroupedCpuBursts.Count)
Add-Line $Lines ("Grouped Memory Growth Events: {0}" -f $GroupedMemBursts.Count)
Add-Line $Lines ("High Priority Findings: {0}" -f $HighPriority.Count)
Add-Line $Lines ("Medium Priority Findings: {0}" -f $MediumPriority.Count)
Add-Line $Lines ("Low Context Findings: {0}" -f $LowContext.Count)
Add-Line $Lines ("Total Findings: {0}" -f ($HighPriority.Count + $MediumPriority.Count + $LowContext.Count))

Write-Bucket $Lines "HIGH PRIORITY" $HighPriority
Write-Bucket $Lines "MEDIUM PRIORITY" $MediumPriority
Write-Bucket $Lines "LOW CONTEXT" $LowContext

Add-Blank $Lines
Add-Line $Lines "This output is an evidence artifact."
Add-Line $Lines "No final conclusion is made at this stage."

Add-Header $Lines "BEHAVIORAL NARRATIVE"
if (($HighPriority.Count + $MediumPriority.Count + $LowContext.Count) -eq 0) {
    Add-Line $Lines "No notable live-change activity was captured during the watch window."
}
else {
    Add-Line $Lines "During the watch window, grouped live-change activity was captured across process, connection, file, persistence, and control surfaces."
    Add-Line $Lines ("Process groups observed: {0}" -f $GroupedProcesses.Count)
    Add-Line $Lines ("Connection groups observed: {0}" -f $GroupedConnections.Count)
    Add-Line $Lines ("File activity groups observed: {0}" -f $GroupedFiles.Count)
    Add-Line $Lines "This narrative is organizational only and does not replace raw review of the grouped findings above."
}

Add-Header $Lines "ANALYST NOTES"
if (($HighPriority.Count + $MediumPriority.Count + $LowContext.Count) -gt 0) {
    Add-Line $Lines "- Raw events were preserved and grouped to reduce repeated line spam without dropping underlying context."
    Add-Line $Lines "- Priority bucketing is intentionally light. Review obvious combined red flags first."
    Add-Line $Lines "- Repeated launches, repeated connections, and repeated file activity are summarized with counts rather than suppressed."
    Add-Line $Lines "- Correlate process, connection, file, persistence, and control changes across modules."
}
else {
    Add-Line $Lines "- No changes surfaced during the watch window."
    Add-Line $Lines "- This does not prove the host is clean. Extend watch time or pivot to Network / Persistence if suspicion remains."
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
Add-Line $Footer "- Obvious combined red flags or strong live-change signals"
Add-Blank $Footer
Add-Line $Footer "MEDIUM PRIORITY:"
Add-Line $Footer "- Worth focused review and correlation"
Add-Blank $Footer
Add-Line $Footer "LOW CONTEXT:"
Add-Line $Footer "- Contextual or supporting observations retained for later analysis"

if ($TopPriority -eq "HIGH") {
    Add-Blank $Footer
    Add-Line $Footer "---"
    Add-Blank $Footer
    Add-Line $Footer "=== ESCALATION REQUIRED ==="
    Add-Blank $Footer
    Add-Line $Footer "High-priority indicators were identified."
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
Write-Host "VELVETEEN SENTINEL WATCH COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Output File: $ReportPath"
Write-Host "System Evidence ID: $SystemEvidenceId"
Write-Host "Elapsed Watch Time: $ElapsedText"
Write-Host "Stop Method: $StopMethod"
Write-Host "Grouped Process Events: $($GroupedProcesses.Count)"
Write-Host "Grouped Connection Events: $($GroupedConnections.Count)"
Write-Host "Grouped File Events: $($GroupedFiles.Count)"
Write-Host "Grouped CPU Burst Events: $($GroupedCpuBursts.Count)"
Write-Host "Grouped Memory Growth Events: $($GroupedMemBursts.Count)"
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

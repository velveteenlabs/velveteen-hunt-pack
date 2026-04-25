<#
VELVETEEN HUNT PACK
SCRIPT: Velveteen-FollowUp-ProcessTrace.ps1
PURPOSE: Follow up on a suspicious process by tracing parent process, child processes,
command line, executable path, network activity, and related context.

READ-ONLY: This script does not kill, delete, quarantine, or modify anything.
#>

param(
    [int]$TargetPid,
    [string]$TargetName
)

$DateTag = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutDir = "$env:USERPROFILE\Desktop\Velveteen-Hunt-Pack-Reports"
$ReportFile = Join-Path $OutDir "Velveteen-FollowUp-ProcessTrace-$DateTag.txt"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $TargetPid -and -not $TargetName) {
    Write-Host ""
    Write-Host "Velveteen Follow-Up: Process Trace" -ForegroundColor Cyan
    Write-Host "Enter either a suspicious PID or process name from another Velveteen report."
    Write-Host ""
    $Choice = Read-Host "Trace by PID or Name? Type PID or NAME"

    if ($Choice -match "PID") {
        $TargetPid = [int](Read-Host "Enter suspicious PID")
    }
    else {
        $TargetName = Read-Host "Enter suspicious process name, example powershell.exe"
    }
}

$Report = @()

$Report += @"
=========================================
VELVETEEN HUNT PACK — PROCESS FOLLOW-UP
=========================================

PHASE:
Follow-Up Investigation

SCRIPT:
Velveteen-FollowUp-ProcessTrace.ps1

PURPOSE:
This script investigates a suspicious process identified by another Velveteen hunt phase.

WHAT THIS SCRIPT DOES:
- Finds the target process by PID or process name
- Captures command line and executable path
- Identifies parent process
- Identifies child processes
- Checks active network connections tied to the process
- Preserves findings in a structured report

WHAT TO LOOK FOR:
- PowerShell, cmd, wscript, cscript, mshta, rundll32, regsvr32, or encoded commands
- Parent/child chains that do not make sense
- Processes launched from Temp, AppData, Downloads, or ProgramData
- Suspicious outbound network connections
- Missing or strange executable paths

IMPORTANT:
This script is READ-ONLY.
It does not terminate, delete, quarantine, or modify anything.

=========================================
"@

# Collect target processes
$AllProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

if ($TargetPid) {
    $TargetProcesses = $AllProcesses | Where-Object { $_.ProcessId -eq $TargetPid }
}
else {
    $TargetProcesses = $AllProcesses | Where-Object {
        $_.Name -like $TargetName -or $_.Name -like "*$TargetName*"
    }
}

$High = @()
$Medium = @()
$Low = @()

if (-not $TargetProcesses) {
    $Report += "`n=== HIGH PRIORITY FINDINGS ==="
    $Report += "No matching process was found. If the process has exited, use EventLog, Artifact, or Correlation reports for historical evidence."
}
else {
    foreach ($Proc in $TargetProcesses) {

        $Parent = $AllProcesses | Where-Object { $_.ProcessId -eq $Proc.ParentProcessId }
        $Children = $AllProcesses | Where-Object { $_.ParentProcessId -eq $Proc.ProcessId }

        $TcpConnections = Get-NetTCPConnection -OwningProcess $Proc.ProcessId -ErrorAction SilentlyContinue

        $SuspiciousScore = 0
        $Reasons = @()

        if ($Proc.CommandLine -match "EncodedCommand|FromBase64String|IEX|Invoke-Expression|DownloadString|WebClient|curl|wget|bitsadmin") {
            $SuspiciousScore += 3
            $Reasons += "Suspicious command-line execution pattern detected"
        }

        if ($Proc.ExecutablePath -match "\\AppData\\|\\Temp\\|\\Downloads\\|\\ProgramData\\") {
            $SuspiciousScore += 2
            $Reasons += "Executable launched from high-risk user-writable path"
        }

        if ($Proc.Name -match "powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32") {
            $SuspiciousScore += 1
            $Reasons += "Living-off-the-land or script-capable process"
        }

        if ($TcpConnections) {
            $SuspiciousScore += 1
            $Reasons += "Process has active network connections"
        }

        $Entry = [PSCustomObject]@{
            Name = $Proc.Name
            PID = $Proc.ProcessId
            ParentPID = $Proc.ParentProcessId
            ParentName = $Parent.Name
            ExecutablePath = $Proc.ExecutablePath
            CommandLine = $Proc.CommandLine
            CreationDate = $Proc.CreationDate
            ChildCount = $Children.Count
            NetworkConnectionCount = $TcpConnections.Count
            Reasons = ($Reasons -join "; ")
        }

        if ($SuspiciousScore -ge 4) {
            $High += $Entry
        }
        elseif ($SuspiciousScore -ge 2) {
            $Medium += $Entry
        }
        else {
            $Low += $Entry
        }

        $Report += "`n========================================="
        $Report += "TARGET PROCESS DETAILS"
        $Report += "========================================="
        $Report += "Name: $($Proc.Name)"
        $Report += "PID: $($Proc.ProcessId)"
        $Report += "Parent PID: $($Proc.ParentProcessId)"
        $Report += "Parent Name: $($Parent.Name)"
        $Report += "Executable Path: $($Proc.ExecutablePath)"
        $Report += "Creation Date: $($Proc.CreationDate)"
        $Report += "Command Line:"
        $Report += "$($Proc.CommandLine)"
        $Report += ""

        $Report += "---- CHILD PROCESSES ----"
        if ($Children) {
            foreach ($Child in $Children) {
                $Report += "Child Name: $($Child.Name)"
                $Report += "Child PID: $($Child.ProcessId)"
                $Report += "Child Path: $($Child.ExecutablePath)"
                $Report += "Child Command Line: $($Child.CommandLine)"
                $Report += ""
            }
        }
        else {
            $Report += "No child processes detected."
        }

        $Report += ""
        $Report += "---- NETWORK CONNECTIONS FOR THIS PROCESS ----"
        if ($TcpConnections) {
            foreach ($Conn in $TcpConnections) {
                $Report += "Local: $($Conn.LocalAddress):$($Conn.LocalPort)"
                $Report += "Remote: $($Conn.RemoteAddress):$($Conn.RemotePort)"
                $Report += "State: $($Conn.State)"
                $Report += ""
            }
        }
        else {
            $Report += "No active TCP connections found for this process."
        }
    }
}

function Add-Bucket {
    param(
        [string]$Title,
        [array]$Items,
        [string]$Description
    )

    $script:Report += "`n========================================="
    $script:Report += $Title
    $script:Report += "========================================="
    $script:Report += $Description
    $script:Report += ""

    if (-not $Items -or $Items.Count -eq 0) {
        $script:Report += "None detected."
    }
    else {
        foreach ($Item in $Items) {
            $script:Report += "Name: $($Item.Name)"
            $script:Report += "PID: $($Item.PID)"
            $script:Report += "Parent: $($Item.ParentName) ($($Item.ParentPID))"
            $script:Report += "Path: $($Item.ExecutablePath)"
            $script:Report += "Created: $($Item.CreationDate)"
            $script:Report += "Children: $($Item.ChildCount)"
            $script:Report += "Network Connections: $($Item.NetworkConnectionCount)"
            $script:Report += "Reasons: $($Item.Reasons)"
            $script:Report += "Command Line: $($Item.CommandLine)"
            $script:Report += ""
        }
    }
}

Add-Bucket "HIGH PRIORITY FINDINGS" $High "Strong process-level concern. These findings combine suspicious command behavior, risky paths, or network activity."
Add-Bucket "MEDIUM PRIORITY FINDINGS" $Medium "Partial concern. These may be benign alone but deserve correlation with network, persistence, and artifact reports."
Add-Bucket "LOW CONTEXT FINDINGS" $Low "Single or weak indicators retained for reference."

$Report += @"

=========================================
ANALYST NOTES
=========================================

Use this report to answer:

1. What launched the suspicious process?
2. Did it spawn anything else?
3. Was it launched from a risky path?
4. Did it make outbound connections?
5. Does the command line show encoded, downloaded, or script-based execution?

Process findings become stronger when they correlate with:
- Network connections
- Persistence entries
- Recently modified files
- Suspicious command lines
- Repeated indicators in Correlation

=========================================
FOLLOW-UP RECOMMENDATIONS
=========================================

If the process path is suspicious, run:

Velveteen-FollowUp-FileTrace.ps1

If network activity appears suspicious, run:

Velveteen-Hunt-Network.ps1

If the process appears tied to startup behavior, run:

Velveteen-Hunt-Persistence.ps1

Then run:

Velveteen-Hunt-Correlation.ps1

=========================================
EVIDENCE + CHAIN OF CUSTODY
=========================================

- Do not delete or modify suspicious files yet.
- Preserve this report with the original timestamp.
- Record who ran the script and why.
- Save hashes of suspicious executable files before remediation.
- Take screenshots if presenting findings to another analyst.
- Keep original reports together in the Velveteen-Hunt-Pack-Reports folder.

Generated:
$DateTag

Report Path:
$ReportFile

=========================================
"@

$Report | Out-File -FilePath $ReportFile -Encoding UTF8
Start-Process notepad.exe $ReportFile

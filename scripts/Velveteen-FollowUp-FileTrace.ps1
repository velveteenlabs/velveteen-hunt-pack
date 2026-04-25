<#
VELVETEEN HUNT PACK
SCRIPT: Velveteen-FollowUp-FileTrace.ps1
PURPOSE: Follow up on a suspicious file by collecting metadata, hashes,
persistence references, scheduled task references, service references, and process references.

READ-ONLY: This script does not delete, quarantine, upload, or modify files.
#>

param(
    [string]$FilePath
)

$DateTag = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutDir = "$env:USERPROFILE\Desktop\Velveteen-Hunt-Pack-Reports"
$ReportFile = Join-Path $OutDir "Velveteen-FollowUp-FileTrace-$DateTag.txt"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $FilePath) {
    Write-Host ""
    Write-Host "Velveteen Follow-Up: File Trace" -ForegroundColor Cyan
    Write-Host "Enter the full suspicious file path from another Velveteen report."
    Write-Host ""
    $FilePath = Read-Host "Suspicious file path"
}

$Report = @()

$Report += @"
=========================================
VELVETEEN HUNT PACK — FILE FOLLOW-UP
=========================================

PHASE:
Follow-Up Investigation

SCRIPT:
Velveteen-FollowUp-FileTrace.ps1

PURPOSE:
This script investigates a suspicious file identified by another Velveteen hunt phase.

WHAT THIS SCRIPT DOES:
- Captures file metadata
- Calculates SHA256 hash
- Checks whether the file is currently running
- Searches common persistence locations for references
- Checks scheduled tasks for references
- Checks services for references
- Preserves findings in a structured report

WHAT TO LOOK FOR:
- Files in AppData, Temp, Downloads, or ProgramData
- Executables or scripts referenced by startup locations
- File paths referenced in scheduled tasks or services
- Hashes that should be searched in VirusTotal or other reputation tools
- Files with recent timestamps and unclear origin

IMPORTANT:
This script is READ-ONLY.
It does not delete, quarantine, upload, or modify anything.

=========================================
"@

$High = @()
$Medium = @()
$Low = @()

if (-not (Test-Path $FilePath)) {
    $Report += "`n=== HIGH PRIORITY FINDINGS ==="
    $Report += "The file path does not currently exist."
    $Report += "This may mean the file was deleted, moved, renamed, or existed only temporarily."
    $Report += "Still correlate the path with EventLog, Persistence, and Correlation reports."
}
else {
    $Item = Get-Item $FilePath -ErrorAction SilentlyContinue
    $Hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction SilentlyContinue

    $Report += "`n========================================="
    $Report += "TARGET FILE DETAILS"
    $Report += "========================================="
    $Report += "File Name: $($Item.Name)"
    $Report += "Full Path: $($Item.FullName)"
    $Report += "Directory: $($Item.DirectoryName)"
    $Report += "Extension: $($Item.Extension)"
    $Report += "Size KB: $([math]::Round($Item.Length / 1KB, 2))"
    $Report += "Created: $($Item.CreationTime)"
    $Report += "Last Modified: $($Item.LastWriteTime)"
    $Report += "Last Accessed: $($Item.LastAccessTime)"
    $Report += "Attributes: $($Item.Attributes)"
    $Report += "SHA256: $($Hash.Hash)"
    $Report += ""

    $SuspiciousScore = 0
    $Reasons = @()

    if ($Item.FullName -match "\\AppData\\|\\Temp\\|\\Downloads\\|\\ProgramData\\") {
        $SuspiciousScore += 2
        $Reasons += "File is located in a high-risk user-writable or staging path"
    }

    if ($Item.Extension -match "\.exe|\.dll|\.ps1|\.bat|\.vbs|\.js|\.lnk") {
        $SuspiciousScore += 1
        $Reasons += "File type can be executable or used for script-based execution"
    }

    if ($Item.LastWriteTime -gt (Get-Date).AddDays(-7)) {
        $SuspiciousScore += 1
        $Reasons += "File was modified recently"
    }

    # Running process references
    $Processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    $RunningRefs = $Processes | Where-Object {
        $_.ExecutablePath -eq $Item.FullName -or $_.CommandLine -like "*$($Item.FullName)*"
    }

    if ($RunningRefs) {
        $SuspiciousScore += 2
        $Reasons += "File is currently referenced by a running process"
    }

    # Registry persistence checks
    $RunKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $RegistryRefs = @()

    foreach ($Key in $RunKeys) {
        if (Test-Path $Key) {
            $Props = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
            foreach ($Prop in $Props.PSObject.Properties) {
                if ($Prop.Value -like "*$($Item.Name)*" -or $Prop.Value -like "*$($Item.FullName)*") {
                    $RegistryRefs += [PSCustomObject]@{
                        Location = $Key
                        Name = $Prop.Name
                        Value = $Prop.Value
                    }
                }
            }
        }
    }

    if ($RegistryRefs) {
        $SuspiciousScore += 3
        $Reasons += "File is referenced in registry startup persistence locations"
    }

    # Scheduled task references
    $TaskRefs = @()

    $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($Task in $Tasks) {
        foreach ($Action in $Task.Actions) {
            $ActionText = "$($Action.Execute) $($Action.Arguments)"
            if ($ActionText -like "*$($Item.Name)*" -or $ActionText -like "*$($Item.FullName)*") {
                $TaskRefs += [PSCustomObject]@{
                    TaskName = $Task.TaskName
                    TaskPath = $Task.TaskPath
                    Action = $ActionText
                    State = $Task.State
                }
            }
        }
    }

    if ($TaskRefs) {
        $SuspiciousScore += 3
        $Reasons += "File is referenced by scheduled task persistence"
    }

    # Service references
    $ServiceRefs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.PathName -like "*$($Item.Name)*" -or $_.PathName -like "*$($Item.FullName)*"
    }

    if ($ServiceRefs) {
        $SuspiciousScore += 3
        $Reasons += "File is referenced by a Windows service"
    }

    $Summary = [PSCustomObject]@{
        Name = $Item.Name
        Path = $Item.FullName
        SHA256 = $Hash.Hash
        Reasons = ($Reasons -join "; ")
        RunningRefs = $RunningRefs.Count
        RegistryRefs = $RegistryRefs.Count
        TaskRefs = $TaskRefs.Count
        ServiceRefs = $ServiceRefs.Count
    }

    if ($SuspiciousScore -ge 5) {
        $High += $Summary
    }
    elseif ($SuspiciousScore -ge 2) {
        $Medium += $Summary
    }
    else {
        $Low += $Summary
    }

    $Report += "`n---- RUNNING PROCESS REFERENCES ----"
    if ($RunningRefs) {
        foreach ($Proc in $RunningRefs) {
            $Report += "Process: $($Proc.Name)"
            $Report += "PID: $($Proc.ProcessId)"
            $Report += "Executable Path: $($Proc.ExecutablePath)"
            $Report += "Command Line: $($Proc.CommandLine)"
            $Report += ""
        }
    }
    else {
        $Report += "No current running process references found."
    }

    $Report += "`n---- REGISTRY STARTUP REFERENCES ----"
    if ($RegistryRefs) {
        foreach ($Ref in $RegistryRefs) {
            $Report += "Location: $($Ref.Location)"
            $Report += "Name: $($Ref.Name)"
            $Report += "Value: $($Ref.Value)"
            $Report += ""
        }
    }
    else {
        $Report += "No registry startup references found in common Run/RunOnce locations."
    }

    $Report += "`n---- SCHEDULED TASK REFERENCES ----"
    if ($TaskRefs) {
        foreach ($Ref in $TaskRefs) {
            $Report += "Task: $($Ref.TaskPath)$($Ref.TaskName)"
            $Report += "State: $($Ref.State)"
            $Report += "Action: $($Ref.Action)"
            $Report += ""
        }
    }
    else {
        $Report += "No scheduled task references found."
    }

    $Report += "`n---- SERVICE REFERENCES ----"
    if ($ServiceRefs) {
        foreach ($Svc in $ServiceRefs) {
            $Report += "Service Name: $($Svc.Name)"
            $Report += "Display Name: $($Svc.DisplayName)"
            $Report += "State: $($Svc.State)"
            $Report += "Start Mode: $($Svc.StartMode)"
            $Report += "Path: $($Svc.PathName)"
            $Report += ""
        }
    }
    else {
        $Report += "No Windows service references found."
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
            $script:Report += "Path: $($Item.Path)"
            $script:Report += "SHA256: $($Item.SHA256)"
            $script:Report += "Running References: $($Item.RunningRefs)"
            $script:Report += "Registry References: $($Item.RegistryRefs)"
            $script:Report += "Scheduled Task References: $($Item.TaskRefs)"
            $script:Report += "Service References: $($Item.ServiceRefs)"
            $script:Report += "Reasons: $($Item.Reasons)"
            $script:Report += ""
        }
    }
}

Add-Bucket "HIGH PRIORITY FINDINGS" $High "Strong file-level concern. File is tied to execution, persistence, service behavior, or multiple suspicious traits."
Add-Bucket "MEDIUM PRIORITY FINDINGS" $Medium "Partial concern. File has suspicious traits but needs correlation with other Velveteen reports."
Add-Bucket "LOW CONTEXT FINDINGS" $Low "Single or weak indicators retained for reference."

$Report += @"

=========================================
ANALYST NOTES
=========================================

Use this report to answer:

1. What is this file?
2. Where is it located?
3. Is it currently running?
4. Is it referenced by startup, tasks, or services?
5. Does the hash need reputation checking?
6. Does the same path appear in other Velveteen reports?

File findings become stronger when they correlate with:
- A running process
- A network connection
- A scheduled task
- A registry Run key
- A service entry
- Repeated appearances in multiple reports

=========================================
FOLLOW-UP RECOMMENDATIONS
=========================================

If the file is running as a process, run:

Velveteen-FollowUp-ProcessTrace.ps1

If the file appears in persistence locations, run:

Velveteen-Hunt-Persistence.ps1

If the file path or hash appears in multiple reports, run:

Velveteen-Hunt-Correlation.ps1

External reputation checks may include:
- VirusTotal
- Hybrid Analysis
- MalwareBazaar
- Internal allowlist / known-good baseline

Do not upload sensitive files unless you understand the privacy implications.

=========================================
EVIDENCE + CHAIN OF CUSTODY
=========================================

- Do not delete or modify suspicious files yet.
- Preserve this report with the original timestamp.
- Record who ran the script and why.
- Save the SHA256 hash before remediation.
- Keep original timestamps intact when possible.
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

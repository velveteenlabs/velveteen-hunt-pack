<#
============================================================
VELVETEEN HUNT PACK
============================================================

MODULE: Persistence Hunt
PHASE: 04
MODE: NON-DESTRUCTIVE

=== PURPOSE ===

Hunt common Windows persistence mechanisms, including startup commands,
Run / RunOnce keys, scheduled tasks, services, startup folder items,
and WMI event subscriptions.

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
  secure GitHub repo, external USB, or known-safe machine

- Treat the analyzed system as UNTRUSTED

- Prefer to:
  - review scripts on a separate clean machine
  - transfer only what is needed to the target system

---

=== WHAT TO LOOK FOR ===

- Auto-start entries pointing to AppData, Temp, ProgramData, Downloads, Desktop, Public, or Recycle Bin
- Scheduled tasks launching PowerShell, cmd, mshta, rundll32, regsvr32, wscript, or cscript
- Services running from user-writable paths
- Missing binaries, unsigned binaries, or unusual command lines
- WMI CommandLineEventConsumer or ActiveScriptEventConsumer entries

Focus on anomalies, not volume.

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# CONFIG
# =========================
$ModuleName = "Persistence Hunt"
$PhaseNumber = "04"
$ScriptName = "Velveteen-Hunt-Persistence"
$Mode = "NON-DESTRUCTIVE"
$ReasonLine = "Persistence hunt for startup entries, scheduled tasks, services, WMI consumers, and autorun mechanisms."

$FollowUpScripts = @(
    "Velveteen-Hunt-Correlation.ps1",
    "Velveteen-FollowUp-ProcessTrace.ps1",
    "Velveteen-FollowUp-FileTrace.ps1",
    "Velveteen-Hunt-LiveProcess.ps1",
    "Velveteen-Hunt-Network.ps1"
)

$OutputRoot = Join-Path $env:USERPROFILE "Desktop\Velveteen-Hunt-Pack-Reports"
$AutoOpenReport = $true
$CaseId = "<case-id>"
$AnalystInitials = "<initials>"

# =========================
# HELPERS
# =========================
function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Add-Line {
    param($Lines, [string]$Text)
    [void]$Lines.Add($Text)
}

function Add-Blank {
    param($Lines)
    [void]$Lines.Add("")
}

function Add-Header {
    param($Lines, [string]$Title)
    Add-Blank $Lines
    Add-Line $Lines ("=" * 68)
    Add-Line $Lines $Title
    Add-Line $Lines ("=" * 68)
}

function Safe-String {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [string]$Value
}

function New-SystemEvidenceId {
    return "SYS-$env:COMPUTERNAME-$(Get-Date -Format 'yyyyMMddHHmmss')"
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

function Test-LolbinCommand {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }

    return ($Text -match "powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil|curl|wget|schtasks|wmic|EncodedCommand|FromBase64String|IEX|DownloadString|Invoke-WebRequest|Invoke-RestMethod")
}

function Get-ExecutableFromCommand {
    param([string]$Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return "" }

    $clean = $Command.Trim()

    if ($clean.StartsWith('"')) {
        $secondQuote = $clean.IndexOf('"', 1)
        if ($secondQuote -gt 1) {
            return $clean.Substring(1, $secondQuote - 1)
        }
    }

    return ($clean -split "\s+")[0]
}

function Get-SignerStatus {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return "Missing" }

    $candidate = $Path.Trim('"')

    if (-not (Test-Path -LiteralPath $candidate)) {
        return "Missing"
    }

    try {
        return [string](Get-AuthenticodeSignature -FilePath $candidate).Status
    }
    catch {
        return "Error"
    }
}

function New-FindingObject {
    param(
        [string]$ReviewPriority,
        [string]$Category,
        [string]$ObjectName,
        [string]$Finding,
        [string]$Why,
        [string]$Path = "",
        [string]$Extra = ""
    )

    return [PSCustomObject]@{
        ReviewPriority = $ReviewPriority
        Category       = $Category
        ObjectName     = $ObjectName
        Finding        = $Finding
        Why            = $Why
        Path           = $Path
        Extra          = $Extra
    }
}

function Add-FindingToBucket {
    param($Bucket, $FindingObject)
    [void]$Bucket.Add($FindingObject)
}

function Write-BucketToReport {
    param($Lines, [string]$Title, $Bucket)

    Add-Header $Lines $Title

    if ($Bucket.Count -eq 0) {
        Add-Line $Lines "No items in this bucket."
        return
    }

    foreach ($Finding in $Bucket) {
        Add-Line $Lines ("Review Priority: {0}" -f $Finding.ReviewPriority)
        Add-Line $Lines ("Category: {0}" -f $Finding.Category)
        Add-Line $Lines ("Object: {0}" -f $Finding.ObjectName)
        if ($Finding.Path)  { Add-Line $Lines ("Path: {0}" -f $Finding.Path) }
        if ($Finding.Extra) { Add-Line $Lines ("Extra: {0}" -f $Finding.Extra) }
        Add-Line $Lines ("Finding: {0}" -f $Finding.Finding)
        Add-Line $Lines ("Why: {0}" -f $Finding.Why)
        Add-Blank $Lines
    }
}

function Open-Report {
    param([string]$Path)
    try {
        Start-Process notepad.exe -ArgumentList "`"$Path`""
    }
    catch {
        try { Invoke-Item -LiteralPath $Path } catch {}
    }
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
# COLLECTION + FINDINGS
# =========================

# Startup Commands
try {
    $StartupCommands = @(Get-CimInstance Win32_StartupCommand)

    foreach ($item in $StartupCommands) {
        $name = Safe-String $item.Name
        $command = Safe-String $item.Command
        $location = Safe-String $item.Location
        $user = Safe-String $item.User
        $exe = Get-ExecutableFromCommand $command
        $signer = Get-SignerStatus $exe

        $isSuspiciousPath = Test-SuspiciousPath $command
        $isLolbin = Test-LolbinCommand $command
        $isUnsigned = $signer -in @("NotSigned","UnknownError","HashMismatch","Error")

        if ($isSuspiciousPath -or $isLolbin -or $isUnsigned) {
            $priority = if ($isSuspiciousPath -and $isLolbin) { "HIGH" } else { "MEDIUM" }

            $finding = New-FindingObject `
                -ReviewPriority $priority `
                -Category "Startup Command" `
                -ObjectName $name `
                -Path $exe `
                -Extra ("Location={0}; User={1}; Signer={2}; Command={3}" -f $location, $user, $signer, $command) `
                -Finding "Startup command contains suspicious path, LOLBin, or trust anomaly." `
                -Why "Startup commands are common persistence points. Suspicious paths, script hosts, or unsigned targets increase review priority."

            if ($priority -eq "HIGH") { Add-FindingToBucket $HighPriority $finding } else { Add-FindingToBucket $MediumPriority $finding }
        }
        else {
            Add-FindingToBucket $LowContext (New-FindingObject `
                -ReviewPriority "LOW" `
                -Category "Startup Command" `
                -ObjectName $name `
                -Path $exe `
                -Extra ("Location={0}; User={1}; Command={2}" -f $location, $user, $command) `
                -Finding "Startup command captured for context." `
                -Why "Benign startup entries are retained as baseline context.")
        }
    }
}
catch {
    Add-FindingToBucket $MediumPriority (New-FindingObject "MEDIUM" "Startup Command Collection" "Win32_StartupCommand" "Unable to collect startup command data." "Collection failure can occur due to permissions or provider issues." "" $_.Exception.Message)
}

# Registry Run Keys
$RunKeyPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $RunKeyPaths) {
    if (Test-Path $path) {
        try {
            $props = Get-ItemProperty -Path $path
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match "^PS") { continue }

                $value = Safe-String $prop.Value
                $exe = Get-ExecutableFromCommand $value
                $signer = Get-SignerStatus $exe
                $isSuspiciousPath = Test-SuspiciousPath $value
                $isLolbin = Test-LolbinCommand $value
                $isUnsigned = $signer -in @("NotSigned","UnknownError","HashMismatch","Error")

                if ($isSuspiciousPath -or $isLolbin -or $isUnsigned) {
                    $priority = if ($isSuspiciousPath -and $isLolbin) { "HIGH" } else { "MEDIUM" }

                    $finding = New-FindingObject `
                        -ReviewPriority $priority `
                        -Category "Registry Run Key" `
                        -ObjectName $prop.Name `
                        -Path $path `
                        -Extra ("Value={0}; ParsedTarget={1}; Signer={2}" -f $value, $exe, $signer) `
                        -Finding "Run key entry contains suspicious path, LOLBin, or trust anomaly." `
                        -Why "Run and RunOnce keys are common persistence locations. Suspicious command content increases concern."

                    if ($priority -eq "HIGH") { Add-FindingToBucket $HighPriority $finding } else { Add-FindingToBucket $MediumPriority $finding }
                }
                else {
                    Add-FindingToBucket $LowContext (New-FindingObject `
                        -ReviewPriority "LOW" `
                        -Category "Registry Run Key" `
                        -ObjectName $prop.Name `
                        -Path $path `
                        -Extra ("Value={0}" -f $value) `
                        -Finding "Run key entry captured for context." `
                        -Why "Known or benign autoruns are retained as baseline context.")
                }
            }
        }
        catch {
            Add-FindingToBucket $MediumPriority (New-FindingObject "MEDIUM" "Registry Run Key" $path "Unable to read Run key." "Permission or registry provider issue prevented collection." $path $_.Exception.Message)
        }
    }
}

# Scheduled Tasks
try {
    $Tasks = @(Get-ScheduledTask)

    foreach ($task in $Tasks) {
        $taskName = "{0}{1}" -f $task.TaskPath, $task.TaskName
        $actions = @($task.Actions | ForEach-Object { "{0} {1}" -f (Safe-String $_.Execute), (Safe-String $_.Arguments) })
        $actionText = ($actions -join " ; ")

        $isMicrosoftPath = $task.TaskPath -match "\\Microsoft\\Windows\\"
        $isSuspiciousPath = Test-SuspiciousPath $actionText
        $isLolbin = Test-LolbinCommand $actionText

        if ($isSuspiciousPath -or $isLolbin) {
            $priority = if ($isSuspiciousPath -and $isLolbin) { "HIGH" } else { "MEDIUM" }

            $finding = New-FindingObject `
                -ReviewPriority $priority `
                -Category "Scheduled Task" `
                -ObjectName $taskName `
                -Extra ("State={0}; Actions={1}" -f $task.State, $actionText) `
                -Finding "Scheduled task action contains suspicious path or LOLBin command." `
                -Why "Scheduled tasks are common persistence mechanisms and can launch scripts, binaries, or LOLBins at logon, idle, or timed intervals."

            if ($priority -eq "HIGH") { Add-FindingToBucket $HighPriority $finding } else { Add-FindingToBucket $MediumPriority $finding }
        }
        elseif (-not $isMicrosoftPath) {
            Add-FindingToBucket $LowContext (New-FindingObject `
                -ReviewPriority "LOW" `
                -Category "Scheduled Task" `
                -ObjectName $taskName `
                -Extra ("State={0}; Actions={1}" -f $task.State, $actionText) `
                -Finding "Non-Microsoft scheduled task captured for context." `
                -Why "Third-party scheduled tasks are common but should remain available for correlation.")
        }
    }
}
catch {
    Add-FindingToBucket $MediumPriority (New-FindingObject "MEDIUM" "Scheduled Task Collection" "Get-ScheduledTask" "Unable to collect scheduled tasks." "Collection failure can occur due to permissions or service issues." "" $_.Exception.Message)
}

# Services
try {
    $Services = @(Get-CimInstance Win32_Service)

    foreach ($svc in $Services) {
        $name = Safe-String $svc.Name
        $display = Safe-String $svc.DisplayName
        $pathName = Safe-String $svc.PathName
        $startMode = Safe-String $svc.StartMode
        $state = Safe-String $svc.State
        $startName = Safe-String $svc.StartName
        $exe = Get-ExecutableFromCommand $pathName
        $signer = Get-SignerStatus $exe

        $isAuto = $startMode -eq "Auto"
        $isSuspiciousPath = Test-SuspiciousPath $pathName
        $isLolbin = Test-LolbinCommand $pathName
        $missing = ($signer -eq "Missing" -and $pathName)
        $isUnsigned = $signer -in @("NotSigned","UnknownError","HashMismatch","Error")

        if ($isAuto -and ($isSuspiciousPath -or $isLolbin -or $isUnsigned -or $missing)) {
            $priority = if ($isSuspiciousPath -and ($isLolbin -or $isUnsigned -or $missing)) { "HIGH" } else { "MEDIUM" }

            $finding = New-FindingObject `
                -ReviewPriority $priority `
                -Category "Auto-Start Service" `
                -ObjectName $name `
                -Path $exe `
                -Extra ("DisplayName={0}; State={1}; StartMode={2}; RunsAs={3}; Signer={4}; PathName={5}" -f $display, $state, $startMode, $startName, $signer, $pathName) `
                -Finding "Auto-start service contains suspicious path, LOLBin, missing binary, or trust anomaly." `
                -Why "Auto-start services provide persistent execution and become more concerning when paired with user-writable paths, script hosts, or invalid trust."

            if ($priority -eq "HIGH") { Add-FindingToBucket $HighPriority $finding } else { Add-FindingToBucket $MediumPriority $finding }
        }
        elseif ($isAuto) {
            Add-FindingToBucket $LowContext (New-FindingObject `
                -ReviewPriority "LOW" `
                -Category "Auto-Start Service" `
                -ObjectName $name `
                -Path $exe `
                -Extra ("DisplayName={0}; State={1}; RunsAs={2}; PathName={3}" -f $display, $state, $startName, $pathName) `
                -Finding "Auto-start service captured for context." `
                -Why "Auto-start services are retained for baseline and correlation.")
        }
    }
}
catch {
    Add-FindingToBucket $MediumPriority (New-FindingObject "MEDIUM" "Service Collection" "Win32_Service" "Unable to collect services." "Collection failure can occur due to permissions or provider issues." "" $_.Exception.Message)
}

# Startup Folders
$StartupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($folder in $StartupFolders) {
    if (Test-Path -LiteralPath $folder) {
        try {
            $items = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue)
            foreach ($item in $items) {
                $isStrong = $item.Extension.ToLowerInvariant() -in @(".exe",".dll",".ps1",".bat",".vbs",".js",".lnk",".cmd")
                $priority = if ($isStrong) { "MEDIUM" } else { "LOW" }

                $finding = New-FindingObject `
                    -ReviewPriority $priority `
                    -Category "Startup Folder Item" `
                    -ObjectName $item.Name `
                    -Path $item.FullName `
                    -Extra ("Extension={0}; Created={1}; LastWrite={2}" -f $item.Extension, $item.CreationTime, $item.LastWriteTime) `
                    -Finding "Startup folder item captured." `
                    -Why "Startup folder contents can launch programs or scripts during user logon."

                if ($priority -eq "MEDIUM") { Add-FindingToBucket $MediumPriority $finding } else { Add-FindingToBucket $LowContext $finding }
            }
        }
        catch {
            Add-FindingToBucket $MediumPriority (New-FindingObject "MEDIUM" "Startup Folder" $folder "Unable to enumerate startup folder." "Permission or file system issue prevented collection." $folder $_.Exception.Message)
        }
    }
}

# WMI Persistence
try {
    $Filters = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue)
    $CommandConsumers = @(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue)
    $ScriptConsumers = @(Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
    $Bindings = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue)

    foreach ($consumer in $CommandConsumers) {
        Add-FindingToBucket $HighPriority (New-FindingObject `
            -ReviewPriority "HIGH" `
            -Category "WMI CommandLineEventConsumer" `
            -ObjectName (Safe-String $consumer.Name) `
            -Extra ("CommandLineTemplate={0}" -f (Safe-String $consumer.CommandLineTemplate)) `
            -Finding "WMI CommandLineEventConsumer found." `
            -Why "CommandLineEventConsumer can provide stealthy persistence by launching commands in response to WMI events.")
    }

    foreach ($consumer in $ScriptConsumers) {
        Add-FindingToBucket $HighPriority (New-FindingObject `
            -ReviewPriority "HIGH" `
            -Category "WMI ActiveScriptEventConsumer" `
            -ObjectName (Safe-String $consumer.Name) `
            -Extra ("ScriptingEngine={0}" -f (Safe-String $consumer.ScriptingEngine)) `
            -Finding "WMI ActiveScriptEventConsumer found." `
            -Why "ActiveScriptEventConsumer can execute script content as WMI persistence and deserves immediate review.")
    }

    foreach ($filter in $Filters) {
        Add-FindingToBucket $LowContext (New-FindingObject `
            -ReviewPriority "LOW" `
            -Category "WMI EventFilter" `
            -ObjectName (Safe-String $filter.Name) `
            -Extra ("Namespace={0}; Query={1}" -f (Safe-String $filter.EventNamespace), (Safe-String $filter.Query)) `
            -Finding "WMI event filter captured for context." `
            -Why "Filters are contextual unless paired with a command/script consumer.")
    }

    foreach ($binding in $Bindings) {
        Add-FindingToBucket $LowContext (New-FindingObject `
            -ReviewPriority "LOW" `
            -Category "WMI Binding" `
            -ObjectName "FilterToConsumerBinding" `
            -Extra ("Filter={0}; Consumer={1}" -f (Safe-String $binding.Filter), (Safe-String $binding.Consumer)) `
            -Finding "WMI filter-to-consumer binding captured." `
            -Why "Bindings connect filters to consumers and should be reviewed with WMI consumers.")
    }
}
catch {
    Add-FindingToBucket $MediumPriority (New-FindingObject "MEDIUM" "WMI Persistence Collection" "root\subscription" "Unable to collect WMI persistence data." "Collection failure can occur due to permission or WMI issues." "" $_.Exception.Message)
}

# =========================
# REPORT BODY
# =========================
Add-Header $Lines "SUMMARY"
Add-Line $Lines ("Startup commands reviewed: {0}" -f $StartupCommands.Count)
Add-Line $Lines ("Run key paths reviewed: {0}" -f $RunKeyPaths.Count)
Add-Line $Lines ("Scheduled tasks reviewed: {0}" -f $Tasks.Count)
Add-Line $Lines ("Services reviewed: {0}" -f $Services.Count)
Add-Line $Lines ("Startup folders reviewed: {0}" -f $StartupFolders.Count)
Add-Line $Lines ("WMI filters reviewed: {0}" -f $Filters.Count)
Add-Line $Lines ("WMI command consumers reviewed: {0}" -f $CommandConsumers.Count)
Add-Line $Lines ("WMI script consumers reviewed: {0}" -f $ScriptConsumers.Count)
Add-Line $Lines ("WMI bindings reviewed: {0}" -f $Bindings.Count)
Add-Line $Lines ("High Priority Findings: {0}" -f $HighPriority.Count)
Add-Line $Lines ("Medium Priority Findings: {0}" -f $MediumPriority.Count)
Add-Line $Lines ("Low Context Findings: {0}" -f $LowContext.Count)
Add-Line $Lines ("Total Findings: {0}" -f ($HighPriority.Count + $MediumPriority.Count + $LowContext.Count))

Write-BucketToReport $Lines "HIGH PRIORITY" $HighPriority
Write-BucketToReport $Lines "MEDIUM PRIORITY" $MediumPriority
Write-BucketToReport $Lines "LOW CONTEXT" $LowContext

Add-Blank $Lines
Add-Line $Lines "This output is an evidence artifact."
Add-Line $Lines "No final conclusion is made at this stage."

Add-Header $Lines "ANALYST NOTES"
if (($HighPriority.Count + $MediumPriority.Count + $LowContext.Count) -gt 0) {
    Add-Line $Lines "- Prioritize persistence entries that combine suspicious path, LOLBin usage, missing binary, or trust anomaly."
    Add-Line $Lines "- WMI CommandLineEventConsumer and ActiveScriptEventConsumer entries should be reviewed immediately."
    Add-Line $Lines "- Services and scheduled tasks are common benign software mechanisms; validate before acting."
    Add-Line $Lines "- Pivot to ProcessTrace or FileTrace for strongest persistence leads."
} else {
    Add-Line $Lines "- No persistence findings were surfaced by the current heuristics."
    Add-Line $Lines "- This does not prove the host is clean. Re-run with elevated permissions if needed."
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
Add-Line $Footer "Timestamp (UTC): $(([DateTime]::UtcNow).ToString("yyyy-MM-dd HH:mm:ss UTC"))"
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
Add-Line $Footer "[$(([DateTime]::UtcNow).ToString("yyyy-MM-dd HH:mm:ss UTC"))]"
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
Add-Line $Footer "- Strong persistence indicators or stealth-style autorun mechanisms"
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
    Add-Line $Footer "High-priority persistence indicators were identified."
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
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "VELVETEEN PERSISTENCE HUNT COMPLETE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Output File: $ReportPath"
Write-Host "System Evidence ID: $SystemEvidenceId"
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

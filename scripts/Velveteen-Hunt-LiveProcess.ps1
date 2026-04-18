<#
============================================================
VELVETEEN HUNT PACK
============================================================

MODULE: Live Process Hunt
PHASE: 01
MODE: NON-DESTRUCTIVE

=== PURPOSE ===

Hunt suspicious live execution, RAT-like behavior, unusual process context,
process-linked network activity, privilege anomalies, trust issues,
resource anomalies, and file/process timeline inconsistencies.

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

- Processes running from AppData, Temp, ProgramData, Public, Downloads, Desktop, or other user-writable paths
- Unsigned or suspiciously signed binaries with network activity, elevated context, or odd parentage
- Elevated/Admin/SYSTEM processes in unusual locations, LOLBin abuse, odd parent-child chains, resource anomalies, and timestamp inconsistencies

Focus on anomalies, not volume.

#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# CONFIG
# =========================
$ModuleName = "Live Process Hunt"
$PhaseNumber = "01"
$ScriptName = "Velveteen-Hunt-LiveProcess"
$Mode = "NON-DESTRUCTIVE"
$ReasonLine = "Initial live process hunt for suspicious execution, RAT-like behavior, and process-linked network activity."

$FollowUpScripts = @(
    "Velveteen-Hunt-Sentinel.ps1",
    "Velveteen-Hunt-Network.ps1",
    "Velveteen-FollowUp-ProcessTrace.ps1",
    "Velveteen-FollowUp-FileTrace.ps1"
)

$OutputRoot = Join-Path $env:USERPROFILE "Desktop\Velveteen-Hunt-Pack-Reports"
$AutoOpenReport = $true
$CaseId = "<case-id>"
$AnalystInitials = "<initials>"

$FutureToleranceMinutes = 5

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
    $p = $Path.ToLowerInvariant()
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
    return $Name.ToLowerInvariant() -in @(
        "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
        "mshta.exe","rundll32.exe","regsvr32.exe"
    )
}

function Get-SignerStatus {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return "Missing"
    }
    try {
        return [string](Get-AuthenticodeSignature -FilePath $Path).Status
    }
    catch {
        return "Error"
    }
}

function Get-OwnerString {
    param($ProcessCim)
    try {
        $owner = Invoke-CimMethod -InputObject $ProcessCim -MethodName GetOwner -ErrorAction Stop
        if ($owner.ReturnValue -eq 0) {
            return "{0}\{1}" -f $owner.Domain, $owner.User
        }
    }
    catch {}
    return "Unknown"
}

function Get-PrivilegeLabel {
    param([string]$Owner)
    if ([string]::IsNullOrWhiteSpace($Owner)) { return "Unknown" }
    if ($Owner -match "SYSTEM") { return "SYSTEM" }
    if ($Owner -match "LOCAL SERVICE") { return "LOCAL SERVICE" }
    if ($Owner -match "NETWORK SERVICE") { return "NETWORK SERVICE" }
    if ($Owner -match "Administrator") { return "AdminLike" }
    return "User/Unknown"
}

function New-FindingObject {
    param(
        [string]$ReviewPriority,
        [string]$Category,
        [string]$ProcessName,
        [string]$ProcessIdText,
        [string]$Finding,
        [string]$Why,
        [string]$Path = "",
        [string]$Extra = ""
    )
    return [PSCustomObject]@{
        ReviewPriority = $ReviewPriority
        Category       = $Category
        ProcessName    = $ProcessName
        ProcessIdText  = $ProcessIdText
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
        Add-Line $Lines ("Process: {0}" -f $Finding.ProcessName)
        Add-Line $Lines ("PID: {0}" -f $Finding.ProcessIdText)
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
$UtcTimestamp = ([DateTime]::UtcNow).ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
$ReportPath = Join-Path $OutputRoot ("{0}_{1}.txt" -f $ScriptName, $TimestampTag)

$Lines = New-Object 'System.Collections.Generic.List[string]'
$HighPriority = New-Object 'System.Collections.Generic.List[object]'
$MediumPriority = New-Object 'System.Collections.Generic.List[object]'
$LowContext = New-Object 'System.Collections.Generic.List[object]'
$Notes = New-Object 'System.Collections.Generic.List[string]'

# =========================
# COLLECTION
# =========================
$Processes = @(Get-CimInstance Win32_Process)
$ProcessById = @{}
$OwnerById = @{}

foreach ($Proc in $Processes) {
    $ProcessIdText = [string]$Proc.ProcessId
    $ProcessById[$ProcessIdText] = $Proc
    $OwnerById[$ProcessIdText] = Get-OwnerString $Proc
}

$Connections = @()
try {
    $Connections = @(Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess)
}
catch {}

$ConnectionsById = @{}
foreach ($Conn in $Connections) {
    $ProcessIdText = [string]$Conn.OwningProcess
    if (-not $ConnectionsById.ContainsKey($ProcessIdText)) {
        $ConnectionsById[$ProcessIdText] = @()
    }
    $ConnectionsById[$ProcessIdText] += $Conn
}

# =========================
# FINDING LOGIC
# =========================
$Now = Get-Date

foreach ($Proc in $Processes) {
    $ProcessIdText = [string]$Proc.ProcessId
    $ProcessName = Safe-String $Proc.Name
    $ProcessPath = Safe-String $Proc.ExecutablePath
    $CommandLine = Safe-String $Proc.CommandLine
    $Owner = $OwnerById[$ProcessIdText]
    $Privilege = Get-PrivilegeLabel $Owner
    $ParentProcessIdText = [string]$Proc.ParentProcessId
    $ParentName = if ($ProcessById.ContainsKey($ParentProcessIdText)) { Safe-String $ProcessById[$ParentProcessIdText].Name } else { "Unknown" }
    $HasNetwork = $ConnectionsById.ContainsKey($ProcessIdText) -and $ConnectionsById[$ProcessIdText].Count -gt 0
    $SignerStatus = Get-SignerStatus $ProcessPath

    $StartTime = $null
    try {
        if ($Proc.CreationDate) {
            $StartTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($Proc.CreationDate)
        }
    }
    catch {}

    $CreationTime = $null
    $LastWriteTime = $null
    if ($ProcessPath -and (Test-Path -LiteralPath $ProcessPath)) {
        try {
            $FileItem = Get-Item -LiteralPath $ProcessPath -ErrorAction Stop
            $CreationTime = $FileItem.CreationTime
            $LastWriteTime = $FileItem.LastWriteTime
        }
        catch {}
    }

    # Suspicious path
    if (Test-SuspiciousPath $ProcessPath) {
        $Priority = if ($HasNetwork -or $Privilege -in @("SYSTEM","AdminLike")) { "HIGH" } else { "MEDIUM" }
        $Finding = New-FindingObject `
            -ReviewPriority $Priority `
            -Category "Suspicious Path" `
            -ProcessName $ProcessName `
            -ProcessIdText $ProcessIdText `
            -Path $ProcessPath `
            -Extra ("Owner=$Owner; Privilege=$Privilege; Parent=$ParentName($ParentProcessIdText)") `
            -Finding "Process executable is running from a user-writable or stealth-favored path." `
            -Why "Stealth malware, staged loaders, and RAT components often execute from AppData, Temp, ProgramData, Public, Downloads, or Desktop rather than trusted application locations."

        if ($Priority -eq "HIGH") { Add-FindingToBucket $HighPriority $Finding } else { Add-FindingToBucket $MediumPriority $Finding }
    }

    # Unsigned or trust anomaly
    if ($SignerStatus -in @("NotSigned","UnknownError","HashMismatch","Error")) {
        $Priority = if ($HasNetwork) { "HIGH" } else { "MEDIUM" }
        $Finding = New-FindingObject `
            -ReviewPriority $Priority `
            -Category "Trust Anomaly" `
            -ProcessName $ProcessName `
            -ProcessIdText $ProcessIdText `
            -Path $ProcessPath `
            -Extra ("SignerStatus=$SignerStatus; Owner=$Owner; Network=$(if($HasNetwork){'Yes'}else{'No'})") `
            -Finding "Process binary is unsigned or signature review did not validate cleanly." `
            -Why "Unsigned or trust-anomalous live binaries become more concerning when paired with suspicious paths, odd parentage, elevation, or network activity."

        if ($Priority -eq "HIGH") { Add-FindingToBucket $HighPriority $Finding } else { Add-FindingToBucket $MediumPriority $Finding }
    }

    # Elevated process in suspicious path
    if (($Privilege -in @("SYSTEM","AdminLike","LOCAL SERVICE","NETWORK SERVICE")) -and (Test-SuspiciousPath $ProcessPath)) {
        $Finding = New-FindingObject `
            -ReviewPriority "HIGH" `
            -Category "Privilege / Path Mismatch" `
            -ProcessName $ProcessName `
            -ProcessIdText $ProcessIdText `
            -Path $ProcessPath `
            -Extra ("Owner=$Owner; Parent=$ParentName($ParentProcessIdText)") `
            -Finding "Elevated or service-level process is running from a suspicious userland or stealth-favored path." `
            -Why "High-privilege execution from user-writable locations is a strong signal for persistence, stealth launchers, tampering, or post-compromise activity."

        Add-FindingToBucket $HighPriority $Finding
    }

    # LOLBin in suspicious context
    if (Test-IsLolbin $ProcessName) {
        $Reasons = @()
        if (Test-SuspiciousPath $ProcessPath) { $Reasons += "SuspiciousPath" }
        if ($HasNetwork) { $Reasons += "NetworkActive" }
        if ($Privilege -in @("SYSTEM","AdminLike")) { $Reasons += "Elevated" }
        if ($ParentName -in @("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","AcroRd32.exe","chrome.exe","msedge.exe","firefox.exe","powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")) {
            $Reasons += "SuspiciousParent"
        }

        if ($Reasons.Count -gt 0) {
            $Finding = New-FindingObject `
                -ReviewPriority "MEDIUM" `
                -Category "LOLBin Context" `
                -ProcessName $ProcessName `
                -ProcessIdText $ProcessIdText `
                -Path $ProcessPath `
                -Extra ("Reasons=$($Reasons -join ','); Owner=$Owner; Parent=$ParentName($ParentProcessIdText); Cmd=$CommandLine") `
                -Finding "Potential LOLBin misuse detected in suspicious context." `
                -Why "Legitimate Windows utilities are commonly abused by loaders, stagers, and malware to blend into normal activity while executing scripts, DLLs, or remote content."

            Add-FindingToBucket $MediumPriority $Finding
        }
    }

    # Network activity
    if ($HasNetwork) {
        $Established = @($ConnectionsById[$ProcessIdText] | Where-Object { $_.State -eq "Established" })
        if ($Established.Count -gt 0) {
            $RemoteText = ($Established | Select-Object -First 3 | ForEach-Object {
                "{0}:{1}" -f $_.RemoteAddress, $_.RemotePort
            }) -join ", "

            $Priority = if ((Test-SuspiciousPath $ProcessPath) -or $SignerStatus -in @("NotSigned","UnknownError","HashMismatch","Error")) { "HIGH" } else { "LOW" }

            $Finding = New-FindingObject `
                -ReviewPriority $Priority `
                -Category "Live Connection" `
                -ProcessName $ProcessName `
                -ProcessIdText $ProcessIdText `
                -Path $ProcessPath `
                -Extra ("Privilege=$Privilege; Owner=$Owner; Remote=$RemoteText") `
                -Finding "Established live connection observed for process." `
                -Why "Live outbound or inbound sessions may support command-and-control, exfiltration, proxying, or benign application behavior. They become more meaningful when paired with suspicious path, trust, or privilege context."

            if ($Priority -eq "HIGH") {
                Add-FindingToBucket $HighPriority $Finding
            } else {
                Add-FindingToBucket $LowContext $Finding
            }
        }
    }

    # Timestamp inconsistencies
    if ($CreationTime) {
        if ($CreationTime -gt $Now.AddMinutes($FutureToleranceMinutes)) {
            $Finding = New-FindingObject `
                -ReviewPriority "LOW" `
                -Category "Timestamp Inconsistency" `
                -ProcessName $ProcessName `
                -ProcessIdText $ProcessIdText `
                -Path $ProcessPath `
                -Extra ("CreationTime=$CreationTime; CurrentTime=$Now") `
                -Finding "Backing file has a future timestamp relative to current system time." `
                -Why "Future timestamps can result from clock issues, copied artifacts, or metadata inconsistencies that deserve review in context."

            Add-FindingToBucket $LowContext $Finding
        }

        if ($LastWriteTime -and $CreationTime -gt $LastWriteTime) {
            $Finding = New-FindingObject `
                -ReviewPriority "LOW" `
                -Category "Timestamp Inconsistency" `
                -ProcessName $ProcessName `
                -ProcessIdText $ProcessIdText `
                -Path $ProcessPath `
                -Extra ("Creation=$CreationTime; LastWrite=$LastWriteTime") `
                -Finding "File creation time occurs after last modification time." `
                -Why "Creation-after-modification can happen for benign reasons, but it can also indicate copied artifacts or metadata inconsistencies worth noting."

            Add-FindingToBucket $LowContext $Finding
        }

        if ($StartTime -and $StartTime -lt $CreationTime.AddSeconds(-30)) {
            $Finding = New-FindingObject `
                -ReviewPriority "MEDIUM" `
                -Category "Timeline Mismatch" `
                -ProcessName $ProcessName `
                -ProcessIdText $ProcessIdText `
                -Path $ProcessPath `
                -Extra ("ProcessStart=$StartTime; FileCreation=$CreationTime") `
                -Finding "Process start time appears earlier than backing file creation time." `
                -Why "Execution preceding file creation can indicate alternate file confusion, replaced binaries, copied artifacts, or timestamp inconsistencies that deserve review."

            Add-FindingToBucket $MediumPriority $Finding
        }
    }

    # Browser / document spawning LOLBin
    if ($ParentName -in @("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","AcroRd32.exe","chrome.exe","msedge.exe","firefox.exe")) {
        if (Test-IsLolbin $ProcessName) {
            $Finding = New-FindingObject `
                -ReviewPriority "HIGH" `
                -Category "Parent / Child Anomaly" `
                -ProcessName $ProcessName `
                -ProcessIdText $ProcessIdText `
                -Path $ProcessPath `
                -Extra ("Parent=$ParentName($ParentProcessIdText); Owner=$Owner; Cmd=$CommandLine") `
                -Finding "Document or browser process appears to have launched a scripting or LOLBin process." `
                -Why "Office, PDF, and browser-parented script or LOLBin execution is a common pattern in malicious delivery, staging, and post-exploitation activity."

            Add-FindingToBucket $HighPriority $Finding
        }
    }
}

# =========================
# REPORT BODY
# =========================
Add-Header $Lines "SUMMARY"
Add-Line $Lines ("Total processes reviewed: {0}" -f $Processes.Count)
Add-Line $Lines ("Total TCP connections reviewed: {0}" -f $Connections.Count)
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
    Add-Line $Lines "- Prioritize combinations of suspicious path, privilege, trust anomalies, and established outbound connections."
    Add-Line $Lines "- Elevated or SYSTEM processes in user-writable locations should be treated seriously."
    Add-Line $Lines "- LOLBin activity is not proof by itself; evaluate path, parentage, command line, and network behavior together."
    Add-Line $Lines "- Timestamp inconsistencies are retained for context and later correlation."
    Add-Line $Lines "- Pivot to ProcessTrace or FileTrace for the strongest leads."
} else {
    Add-Line $Lines "- No process-level findings were surfaced by the current heuristics."
    Add-Line $Lines "- If suspicion remains, run Sentinel next to catch short-lived or respawning behavior."
}
foreach ($Note in $Notes) {
    Add-Line $Lines "- $Note"
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
Add-Line $Footer "- Strong combined signals or high-interest execution context"
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
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "VELVETEEN LIVE PROCESS HUNT COMPLETE" -ForegroundColor Cyan
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

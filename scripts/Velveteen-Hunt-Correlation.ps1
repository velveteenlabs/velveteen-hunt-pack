<#
VELVETEEN HUNT PACK
SCRIPT: Velveteen-Hunt-Correlation.ps1
PURPOSE: Correlate findings across existing Velveteen Hunt Pack reports.

READ-ONLY:
This script does not modify the system. It only reads existing Velveteen report files
and generates correlation output.
#>

# ================================
# CONFIGURATION
# ================================

$GenerateHTML = $true
$DateTag = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportDir = "$env:USERPROFILE\Desktop\Velveteen-Hunt-Pack-Reports"

$TxtReport = Join-Path $ReportDir "Velveteen-Correlation-$DateTag.txt"
$HtmlReport = Join-Path $ReportDir "Velveteen-Correlation-$DateTag.html"

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null

# ================================
# HELPER FUNCTIONS
# ================================

function Add-Indicator {
    param(
        [hashtable]$Store,
        [string]$Type,
        [string]$Value,
        [string]$SourceFile,
        [string]$Line
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return }

    $CleanValue = $Value.Trim()

    if (-not $Store.ContainsKey($CleanValue)) {
        $Store[$CleanValue] = [PSCustomObject]@{
            Type        = $Type
            Value       = $CleanValue
            Count       = 0
            SourceFiles = New-Object System.Collections.Generic.List[string]
            Lines       = New-Object System.Collections.Generic.List[string]
        }
    }

    $Store[$CleanValue].Count++

    if (-not $Store[$CleanValue].SourceFiles.Contains($SourceFile)) {
        $Store[$CleanValue].SourceFiles.Add($SourceFile)
    }

    if ($Line) {
        $Store[$CleanValue].Lines.Add($Line)
    }
}

function Is-SuspiciousPath {
    param([string]$Path)

    if ($Path -match "\\AppData\\|\\Temp\\|\\Downloads\\|\\ProgramData\\|\\Users\\Public\\|\\Startup\\") {
        return $true
    }

    return $false
}

function Is-SuspiciousCommand {
    param([string]$Command)

    if ($Command -match "EncodedCommand|FromBase64String|Invoke-Expression|IEX|DownloadString|WebClient|curl|wget|bitsadmin|mshta|regsvr32|rundll32|wscript|cscript") {
        return $true
    }

    return $false
}

function HtmlEncode {
    param([string]$Text)

    if ($null -eq $Text) { return "" }

    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Add-Finding {
    param(
        [array]$Bucket,
        [string]$Title,
        [string]$WhyItMatters,
        [string]$Evidence,
        [string]$RecommendedFollowUp
    )

    $Bucket += [PSCustomObject]@{
        Title               = $Title
        WhyItMatters         = $WhyItMatters
        Evidence             = $Evidence
        RecommendedFollowUp  = $RecommendedFollowUp
    }

    return $Bucket
}

# ================================
# HEADER
# ================================

$Header = @"
=========================================
VELVETEEN HUNT PACK — CORRELATION REPORT
=========================================

PHASE:
Correlation / Analysis Brain

SCRIPT:
Velveteen-Hunt-Correlation.ps1

PURPOSE:
This script reads existing Velveteen Hunt Pack reports and correlates repeated indicators
across phases.

WHAT THIS SCRIPT DOES:
- Reads prior TXT reports from:
  Desktop\Velveteen-Hunt-Pack-Reports

- Extracts potential indicators:
  - Process names
  - File paths
  - Remote IPs / endpoints
  - Command lines
  - Hashes
  - Registry paths
  - Scheduled task references
  - Service references

- Identifies repeated indicators across reports
- Correlates process, network, persistence, artifact, and follow-up evidence
- Promotes multiple weak or medium signals into higher concern when patterns align

WHAT TO LOOK FOR:
- Same process, file, IP, hash, or path appearing in multiple reports
- Suspicious paths appearing in persistence-related context
- Script interpreters tied to network or file activity
- Encoded or download-style command lines
- Remote endpoints repeated across reports
- Evidence chains that suggest process → file → network → persistence

IMPORTANT:
This script is READ-ONLY.
It does not delete, quarantine, kill, upload, or modify anything.

=========================================
"@

# ================================
# LOAD REPORTS
# ================================

$ReportFiles = Get-ChildItem -Path $ReportDir -Filter "Velveteen-*.txt" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike "Velveteen-Correlation-*" }

$Indicators = @{}

$ProcessNames = @{}
$FilePaths = @{}
$RemoteIPs = @{}
$Commands = @{}
$Hashes = @{}
$RegistryRefs = @{}
$TaskRefs = @{}
$ServiceRefs = @{}

$ReportPhaseMap = @{}

foreach ($File in $ReportFiles) {
    $Content = Get-Content $File.FullName -ErrorAction SilentlyContinue

    if ($File.Name -match "LiveProcess") { $ReportPhaseMap[$File.Name] = "Process" }
    elseif ($File.Name -match "Network") { $ReportPhaseMap[$File.Name] = "Network" }
    elseif ($File.Name -match "Persistence") { $ReportPhaseMap[$File.Name] = "Persistence" }
    elseif ($File.Name -match "Artifact") { $ReportPhaseMap[$File.Name] = "Artifact" }
    elseif ($File.Name -match "Sentinel") { $ReportPhaseMap[$File.Name] = "Sentinel" }
    elseif ($File.Name -match "FollowUp-ProcessTrace") { $ReportPhaseMap[$File.Name] = "Process Follow-Up" }
    elseif ($File.Name -match "FollowUp-FileTrace") { $ReportPhaseMap[$File.Name] = "File Follow-Up" }
    else { $ReportPhaseMap[$File.Name] = "Unknown" }

    foreach ($Line in $Content) {

        # Process names
        if ($Line -match "(Process|Name|Image Name):\s*([A-Za-z0-9_\-\.]+\.exe)") {
            Add-Indicator -Store $ProcessNames -Type "Process" -Value $Matches[2] -SourceFile $File.Name -Line $Line
        }

        # File paths
        if ($Line -match "([A-Za-z]:\\[^\`"\<\>\|]+)") {
            $PathMatch = $Matches[1].Trim()
            Add-Indicator -Store $FilePaths -Type "FilePath" -Value $PathMatch -SourceFile $File.Name -Line $Line
        }

        # Remote IPs
        if ($Line -match "\b(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b") {
            $IP = $Matches[0]
            if ($IP -notmatch "^127\.|^0\.|^255\.|^169\.254\.|^224\.|^239\.") {
                Add-Indicator -Store $RemoteIPs -Type "RemoteIP" -Value $IP -SourceFile $File.Name -Line $Line
            }
        }

        # Command lines
        if ($Line -match "Command Line:\s*(.+)$") {
            Add-Indicator -Store $Commands -Type "CommandLine" -Value $Matches[1] -SourceFile $File.Name -Line $Line
        }
        elseif ($Line -match "CommandLine:\s*(.+)$") {
            Add-Indicator -Store $Commands -Type "CommandLine" -Value $Matches[1] -SourceFile $File.Name -Line $Line
        }

        # SHA256 hashes
        if ($Line -match "\b[A-Fa-f0-9]{64}\b") {
            Add-Indicator -Store $Hashes -Type "SHA256" -Value $Matches[0] -SourceFile $File.Name -Line $Line
        }

        # Registry references
        if ($Line -match "HKLM:\\|HKCU:\\|RunOnce|CurrentVersion\\Run") {
            Add-Indicator -Store $RegistryRefs -Type "Registry" -Value $Line.Trim() -SourceFile $File.Name -Line $Line
        }

        # Scheduled tasks
        if ($Line -match "Task:|Task Name:|TaskPath|Scheduled Task") {
            Add-Indicator -Store $TaskRefs -Type "ScheduledTask" -Value $Line.Trim() -SourceFile $File.Name -Line $Line
        }

        # Services
        if ($Line -match "Service Name:|Display Name:|Start Mode:|PathName") {
            Add-Indicator -Store $ServiceRefs -Type "Service" -Value $Line.Trim() -SourceFile $File.Name -Line $Line
        }
    }
}

# ================================
# CORRELATION LOGIC
# ================================

$High = @()
$Medium = @()
$Low = @()

foreach ($Item in $ProcessNames.Values) {
    if ($Item.SourceFiles.Count -ge 3) {
        $High = Add-Finding $High "Repeated process across 3+ reports: $($Item.Value)" `
            "A process appearing across multiple hunt phases may indicate a meaningful execution pattern rather than a one-off observation." `
            "Seen $($Item.Count) times across: $($Item.SourceFiles -join ', ')" `
            "Run Velveteen-FollowUp-ProcessTrace.ps1 for this process."
    }
    elseif ($Item.SourceFiles.Count -eq 2) {
        $Medium = Add-Finding $Medium "Repeated process across 2 reports: $($Item.Value)" `
            "This process may be worth checking if it appears with network, artifact, or persistence evidence." `
            "Seen across: $($Item.SourceFiles -join ', ')" `
            "Review LiveProcess and Network reports, then run ProcessTrace if suspicious."
    }
    else {
        $Low = Add-Finding $Low "Single process indicator: $($Item.Value)" `
            "Single process observation retained for reference." `
            "Seen in: $($Item.SourceFiles -join ', ')" `
            "No immediate action unless other context supports concern."
    }
}

foreach ($Item in $FilePaths.Values) {
    $SuspiciousPath = Is-SuspiciousPath $Item.Value
    $AppearsInPersistence = ($Item.SourceFiles -join " ") -match "Persistence|FileTrace"

    if ($Item.SourceFiles.Count -ge 3 -or ($SuspiciousPath -and $AppearsInPersistence)) {
        $High = Add-Finding $High "High-risk file/path correlation: $($Item.Value)" `
            "This path appears repeatedly or appears in persistence-related context. User-writable paths tied to persistence deserve immediate review." `
            "Seen $($Item.Count) times across: $($Item.SourceFiles -join ', ')" `
            "Run Velveteen-FollowUp-FileTrace.ps1 for this path."
    }
    elseif ($Item.SourceFiles.Count -eq 2 -or $SuspiciousPath) {
        $Medium = Add-Finding $Medium "Suspicious or repeated path: $($Item.Value)" `
            "This path is repeated or located in a directory commonly abused for staging, payloads, or persistence." `
            "Seen across: $($Item.SourceFiles -join ', ')" `
            "Review Artifact and Persistence reports."
    }
    else {
        $Low = Add-Finding $Low "Single file/path indicator: $($Item.Value)" `
            "Single path retained for reference." `
            "Seen in: $($Item.SourceFiles -join ', ')" `
            "No immediate action unless it matches a known suspicious file."
    }
}

foreach ($Item in $RemoteIPs.Values) {
    if ($Item.SourceFiles.Count -ge 2) {
        $High = Add-Finding $High "Repeated remote endpoint: $($Item.Value)" `
            "A remote endpoint appearing across multiple reports may indicate repeated outbound communication or beacon-like behavior." `
            "Seen $($Item.Count) times across: $($Item.SourceFiles -join ', ')" `
            "Review Network report and correlate with ProcessTrace."
    }
    else {
        $Low = Add-Finding $Low "Single remote endpoint: $($Item.Value)" `
            "Single IP retained for context. One IP alone is not proof of malicious activity." `
            "Seen in: $($Item.SourceFiles -join ', ')" `
            "Check ownership/reputation if process context looks suspicious."
    }
}

foreach ($Item in $Commands.Values) {
    $SuspiciousCommand = Is-SuspiciousCommand $Item.Value

    if ($SuspiciousCommand -and $Item.SourceFiles.Count -ge 2) {
        $High = Add-Finding $High "Suspicious command line repeated across reports" `
            "Encoded, downloaded, or script-based execution appearing across reports is a strong signal of concern." `
            "Command: $($Item.Value) | Sources: $($Item.SourceFiles -join ', ')" `
            "Run ProcessTrace and FileTrace based on any process or path inside the command."
    }
    elseif ($SuspiciousCommand) {
        $Medium = Add-Finding $Medium "Suspicious command line pattern" `
            "This command contains script, download, encoded, or living-off-the-land behavior that may need validation." `
            "Command: $($Item.Value) | Source: $($Item.SourceFiles -join ', ')" `
            "Review the parent process and any referenced file paths."
    }
    else {
        $Low = Add-Finding $Low "Command line retained for reference" `
            "Command line did not match the current suspicious-pattern rules but is retained for analyst review." `
            "Command: $($Item.Value)" `
            "Review only if tied to another indicator."
    }
}

foreach ($Item in $Hashes.Values) {
    if ($Item.SourceFiles.Count -ge 2) {
        $Medium = Add-Finding $Medium "Repeated SHA256 hash: $($Item.Value)" `
            "Repeated hash may represent the same file appearing across multiple phases." `
            "Seen across: $($Item.SourceFiles -join ', ')" `
            "Check reputation and run FileTrace on the associated path."
    }
    else {
        $Low = Add-Finding $Low "Single SHA256 hash: $($Item.Value)" `
            "Hash retained for reputation checking." `
            "Seen in: $($Item.SourceFiles -join ', ')" `
            "Check VirusTotal, MalwareBazaar, Hybrid Analysis, or internal allowlist."
    }
}

foreach ($Item in $RegistryRefs.Values) {
    $Medium = Add-Finding $Medium "Registry persistence-related reference" `
        "Registry Run/RunOnce references may indicate startup behavior. Validate whether the referenced file is expected." `
        "$($Item.Value) | Source: $($Item.SourceFiles -join ', ')" `
        "Run FileTrace for referenced files and review Persistence report."
}

foreach ($Item in $TaskRefs.Values) {
    $Medium = Add-Finding $Medium "Scheduled task-related reference" `
        "Scheduled tasks are a common persistence mechanism. Validate task action, path, and owner." `
        "$($Item.Value) | Source: $($Item.SourceFiles -join ', ')" `
        "Review Persistence report and run FileTrace on referenced executables."
}

foreach ($Item in $ServiceRefs.Values) {
    $Medium = Add-Finding $Medium "Service-related reference" `
        "Services can provide durable persistence. Validate service path, start mode, and binary location." `
        "$($Item.Value) | Source: $($Item.SourceFiles -join ', ')" `
        "Review Persistence report and run FileTrace on referenced binaries."
}

# ================================
# BUILD TXT REPORT
# ================================

$Txt = @()
$Txt += $Header

$Txt += "`n========================================="
$Txt += "SOURCE REPORTS READ"
$Txt += "========================================="

if (-not $ReportFiles -or $ReportFiles.Count -eq 0) {
    $Txt += "No prior Velveteen TXT reports were found."
    $Txt += "Run LiveProcess, Network, Persistence, Artifact, or Follow-Up scripts first."
}
else {
    foreach ($File in $ReportFiles) {
        $Txt += "$($File.Name) | Phase Guess: $($ReportPhaseMap[$File.Name]) | Last Modified: $($File.LastWriteTime)"
    }
}

function Add-TxtBucket {
    param(
        [string]$Title,
        [array]$Items,
        [string]$Description
    )

    $script:Txt += "`n========================================="
    $script:Txt += $Title
    $script:Txt += "========================================="
    $script:Txt += $Description
    $script:Txt += ""

    if (-not $Items -or $Items.Count -eq 0) {
        $script:Txt += "None detected."
    }
    else {
        $i = 1
        foreach ($Item in $Items) {
            $script:Txt += "[$i] $($Item.Title)"
            $script:Txt += "Why it matters: $($Item.WhyItMatters)"
            $script:Txt += "Evidence: $($Item.Evidence)"
            $script:Txt += "Recommended follow-up: $($Item.RecommendedFollowUp)"
            $script:Txt += ""
            $i++
        }
    }
}

Add-TxtBucket "HIGH PRIORITY FINDINGS" $High "Strong correlation patterns. These deserve first review."
Add-TxtBucket "MEDIUM PRIORITY FINDINGS" $Medium "Repeat signals, partial correlations, or persistence-related context that needs validation."
Add-TxtBucket "LOW CONTEXT FINDINGS" $Low "Single indicators retained for reference."

$Txt += @"

=========================================
ANALYST NOTES
=========================================

How to interpret this report:

- Correlation does not automatically prove compromise.
- A single indicator may be benign.
- Multiple weak indicators become more meaningful when they line up across reports.
- Stronger patterns include:
  process + network
  process + suspicious file path
  file path + persistence
  encoded command + repeated appearance
  remote endpoint + suspicious process context

Think in chains:

1. What process appeared?
2. What launched it?
3. What file path did it use?
4. Did it connect outward?
5. Did it establish persistence?
6. Does the same indicator appear in more than one report?

=========================================
FOLLOW-UP RECOMMENDATIONS
=========================================

For suspicious processes:
Run Velveteen-FollowUp-ProcessTrace.ps1

For suspicious files or paths:
Run Velveteen-FollowUp-FileTrace.ps1

For stale evidence:
Rerun the relevant hunt script:
- Velveteen-Hunt-LiveProcess.ps1
- Velveteen-Hunt-Network.ps1
- Velveteen-Hunt-Persistence.ps1
- Velveteen-Hunt-Artifact.ps1

For full review:
Keep all TXT reports together in:
Desktop\Velveteen-Hunt-Pack-Reports

=========================================
EVIDENCE + CHAIN OF CUSTODY
=========================================

- Do not delete or modify suspicious files based only on correlation.
- Preserve original reports.
- Record who ran each script, when, and why.
- Hash important report files if preserving for evidence.
- Export or copy the full report folder before remediation.
- Keep analyst notes separate from raw observations when possible.
- Treat this correlation report as an analysis layer, not the original evidence.

Generated:
$DateTag

TXT Report Path:
$TxtReport

HTML Report Path:
$HtmlReport

=========================================
"@

$Txt | Out-File -FilePath $TxtReport -Encoding UTF8

# ================================
# BUILD HTML REPORT
# ================================

if ($GenerateHTML) {

    function Build-HtmlBucket {
        param(
            [string]$Title,
            [array]$Items,
            [string]$ClassName,
            [string]$Description
        )

        $Block = "<section class='bucket $ClassName'>"
        $Block += "<h2>$(HtmlEncode $Title)</h2>"
        $Block += "<p class='desc'>$(HtmlEncode $Description)</p>"

        if (-not $Items -or $Items.Count -eq 0) {
            $Block += "<div class='finding empty'>None detected.</div>"
        }
        else {
            foreach ($Item in $Items) {
                $Block += "<div class='finding'>"
                $Block += "<h3>$(HtmlEncode $Item.Title)</h3>"
                $Block += "<p><strong>Why it matters:</strong> $(HtmlEncode $Item.WhyItMatters)</p>"
                $Block += "<pre>$(HtmlEncode $Item.Evidence)</pre>"
                $Block += "<p><strong>Recommended follow-up:</strong> $(HtmlEncode $Item.RecommendedFollowUp)</p>"
                $Block += "</div>"
            }
        }

        $Block += "</section>"
        return $Block
    }

    $SourceRows = ""

    foreach ($File in $ReportFiles) {
        $SourceRows += "<tr><td>$(HtmlEncode $File.Name)</td><td>$(HtmlEncode $ReportPhaseMap[$File.Name])</td><td>$(HtmlEncode $File.LastWriteTime)</td></tr>"
    }

    if (-not $SourceRows) {
        $SourceRows = "<tr><td colspan='3'>No prior Velveteen TXT reports found.</td></tr>"
    }

    $HighHtml = Build-HtmlBucket "HIGH PRIORITY FINDINGS" $High "high" "Strong correlation patterns. Review these first."
    $MediumHtml = Build-HtmlBucket "MEDIUM PRIORITY FINDINGS" $Medium "medium" "Repeat signals, partial correlations, and persistence-related context."
    $LowHtml = Build-HtmlBucket "LOW CONTEXT FINDINGS" $Low "low" "Single indicators retained for reference."

    $Html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Velveteen Correlation Report</title>
<style>
body {
    font-family: Consolas, Arial, sans-serif;
    background: #111;
    color: #e8e8e8;
    margin: 0;
    padding: 0;
}
header {
    background: #1f102f;
    padding: 24px;
    border-bottom: 2px solid #8f5cff;
}
header h1 {
    margin: 0;
    color: #ffffff;
}
header p {
    color: #d8c9ff;
}
main {
    padding: 24px;
}
.card {
    background: #1b1b1b;
    border: 1px solid #333;
    border-radius: 10px;
    padding: 18px;
    margin-bottom: 20px;
}
.bucket {
    border-radius: 10px;
    padding: 18px;
    margin-bottom: 24px;
}
.bucket h2 {
    margin-top: 0;
}
.high {
    border: 1px solid #ff4b5c;
    background: #2a1115;
}
.medium {
    border: 1px solid #ffb347;
    background: #2b2112;
}
.low {
    border: 1px solid #888;
    background: #1c1c1c;
}
.finding {
    background: #111;
    border: 1px solid #333;
    border-radius: 8px;
    padding: 14px;
    margin: 12px 0;
}
.finding h3 {
    margin-top: 0;
    color: #ffffff;
}
pre {
    white-space: pre-wrap;
    word-wrap: break-word;
    background: #050505;
    border: 1px solid #333;
    padding: 10px;
    border-radius: 6px;
    color: #d8d8d8;
}
table {
    width: 100%;
    border-collapse: collapse;
}
th, td {
    border: 1px solid #333;
    padding: 8px;
    text-align: left;
}
th {
    background: #25113b;
}
.desc {
    color: #cccccc;
}
.footer {
    color: #bbbbbb;
    font-size: 0.9em;
}
</style>
</head>
<body>
<header>
<h1>Velveteen Hunt Pack — Correlation Report</h1>
<p>Analysis brain output generated on $DateTag</p>
</header>

<main>

<div class="card">
<h2>Purpose</h2>
<p>This report correlates existing Velveteen TXT reports from the hunt pack folder. It identifies repeated indicators, cross-report patterns, and cases where multiple weak signals combine into stronger concern.</p>
<p><strong>Read-only:</strong> this script does not modify, delete, quarantine, kill, or upload anything.</p>
</div>

<div class="card">
<h2>Source Reports Read</h2>
<table>
<tr><th>Report</th><th>Phase Guess</th><th>Last Modified</th></tr>
$SourceRows
</table>
</div>

$HighHtml
$MediumHtml
$LowHtml

<div class="card">
<h2>Analyst Notes</h2>
<p>Correlation does not automatically prove compromise. A single indicator may be benign. Multiple weak indicators become more meaningful when they align across process, network, artifact, persistence, and follow-up reports.</p>
<pre>
Think in chains:

1. What process appeared?
2. What launched it?
3. What file path did it use?
4. Did it connect outward?
5. Did it establish persistence?
6. Does the same indicator appear in more than one report?
</pre>
</div>

<div class="card">
<h2>Follow-Up Recommendations</h2>
<pre>
For suspicious processes:
Velveteen-FollowUp-ProcessTrace.ps1

For suspicious files or paths:
Velveteen-FollowUp-FileTrace.ps1

For stale evidence:
Rerun LiveProcess, Network, Persistence, or Artifact.

For evidence preservation:
Keep all TXT and HTML reports together in Desktop\Velveteen-Hunt-Pack-Reports.
</pre>
</div>

<div class="card footer">
<h2>Evidence + Chain of Custody</h2>
<p>Do not delete or modify suspicious files based only on correlation. Preserve original reports. Record who ran each script, when, and why. Hash important report files if preserving for evidence. Treat this as an analysis layer, not the original evidence.</p>
<p><strong>TXT Report:</strong> $(HtmlEncode $TxtReport)</p>
<p><strong>HTML Report:</strong> $(HtmlEncode $HtmlReport)</p>
</div>

</main>
</body>
</html>
"@

    $Html | Out-File -FilePath $HtmlReport -Encoding UTF8
}

# ================================
# AUTO-OPEN REPORTS
# ================================

Start-Process notepad.exe $TxtReport

if ($GenerateHTML -and (Test-Path $HtmlReport)) {
    Start-Process $HtmlReport
}

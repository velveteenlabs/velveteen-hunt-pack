# ================================
# Velveteen Hunt Pack
# Script: Velveteen-Hunt-Artifact.ps1
# Phase: Artifact Hunting (File System Analysis)
# ================================

# === CONFIGURATION ===
$DateTag = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$OutDir = "$env:USERPROFILE\Desktop\Velveteen-Hunt-Pack-Reports"
$ReportFile = Join-Path $OutDir "Velveteen-Artifact-$DateTag.txt"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# === HEADER ===
$Header = @"
=========================================
VELVETEEN HUNT PACK — ARTIFACT ANALYSIS
=========================================

PHASE: Artifact Hunt
PURPOSE:
Identify suspicious files and payload artifacts that may indicate malware, persistence, or execution staging.

WHAT THIS SCRIPT DOES:
- Scans high-risk directories
- Identifies suspicious file types
- Flags recently modified executables/scripts
- Detects unusual naming patterns

WHAT TO LOOK FOR:
- Executables in Temp/AppData
- Recently modified files with no clear origin
- Script files (.ps1/.vbs/.js/.bat) in user directories
- Suspicious naming (update.exe, helper.exe, random strings)

NOTE:
This script is READ-ONLY and does NOT modify the system.

=========================================
"@

# === DATA COLLECTION ===

$TargetDirs = @(
    "$env:USERPROFILE\AppData\Local\Temp",
    "$env:USERPROFILE\AppData\Roaming",
    "$env:USERPROFILE\Downloads",
    "$env:ProgramData"
)

$SuspiciousExtensions = @("*.exe","*.dll","*.ps1","*.bat","*.vbs","*.js","*.lnk")

$RecentThreshold = (Get-Date).AddDays(-7)

$Findings = @()

foreach ($dir in $TargetDirs) {
    if (Test-Path $dir) {
        foreach ($ext in $SuspiciousExtensions) {
            $files = Get-ChildItem -Path $dir -Filter $ext -Recurse -ErrorAction SilentlyContinue

            foreach ($file in $files) {
                $Findings += [PSCustomObject]@{
                    Name = $file.Name
                    FullPath = $file.FullName
                    LastWrite = $file.LastWriteTime
                    SizeKB = [math]::Round($file.Length / 1KB, 2)
                }
            }
        }
    }
}

# === ANALYSIS ===

$High = @()
$Medium = @()
$Low = @()

foreach ($f in $Findings) {

    $isRecent = $f.LastWrite -gt $RecentThreshold
    $path = $f.FullPath.ToLower()

    $suspiciousName = $f.Name -match "update|helper|service|temp|random|123|abc"

    if ($path -match "temp" -and $f.Name -match "\.exe|\.ps1|\.bat") {
        $High += $f
    }
    elseif ($isRecent -and $suspiciousName) {
        $Medium += $f
    }
    else {
        $Low += $f
    }
}

# === REPORT BUILD ===

$Report = @()
$Report += $Header

# HIGH PRIORITY
$Report += "`n=== HIGH PRIORITY FINDINGS ==="
$Report += "Indicators that strongly suggest malicious or unauthorized activity.`n"

if ($High.Count -eq 0) {
    $Report += "None detected."
} else {
    foreach ($item in $High) {
        $Report += "Name: $($item.Name)"
        $Report += "Path: $($item.FullPath)"
        $Report += "Last Modified: $($item.LastWrite)"
        $Report += "Size (KB): $($item.SizeKB)"
        $Report += ""
    }
}

# MEDIUM PRIORITY
$Report += "`n=== MEDIUM PRIORITY FINDINGS ==="
$Report += "Repeated or suspicious patterns that may require correlation.`n"

if ($Medium.Count -eq 0) {
    $Report += "None detected."
} else {
    foreach ($item in $Medium) {
        $Report += "Name: $($item.Name)"
        $Report += "Path: $($item.FullPath)"
        $Report += "Last Modified: $($item.LastWrite)"
        $Report += "Size (KB): $($item.SizeKB)"
        $Report += ""
    }
}

# LOW CONTEXT
$Report += "`n=== LOW CONTEXT FINDINGS ==="
$Report += "Single-instance or baseline artifacts for reference.`n"

if ($Low.Count -eq 0) {
    $Report += "None detected."
} else {
    foreach ($item in $Low) {
        $Report += "Name: $($item.Name)"
        $Report += "Path: $($item.FullPath)"
        $Report += "Last Modified: $($item.LastWrite)"
        $Report += "Size (KB): $($item.SizeKB)"
        $Report += ""
    }
}

# === ANALYST NOTES ===
$Report += @"

=========================================
ANALYST NOTES
=========================================

- Focus on HIGH PRIORITY entries first.
- Cross-reference these with:
    → Running processes (LiveProcess)
    → Network connections (Network)
    → Persistence entries (Persistence)

- Pay attention to:
    → Files in Temp that are executable
    → Scripts in user directories
    → Recently modified suspicious files

- Individual findings may seem benign.
  Correlation across multiple scripts increases confidence.

=========================================
FOLLOW-UP ACTIONS
=========================================

Recommended next steps:

1. Run:
   Velveteen-FollowUp-ProcessTrace.ps1
   → Investigate process execution chain

2. Run:
   Velveteen-FollowUp-FileTrace.ps1
   → Investigate file persistence and references

3. Correlate:
   Velveteen-Hunt-Correlation.ps1
   → Identify patterns across all phases

=========================================
EVIDENCE HANDLING
=========================================

- DO NOT delete files yet
- Preserve paths and timestamps
- Capture hashes before any remediation
- Maintain chain-of-custody documentation

=========================================

Generated: $DateTag
=========================================
"@

# === WRITE REPORT ===
$Report | Out-File -FilePath $ReportFile -Encoding UTF8

# === AUTO-OPEN ===
Start-Process notepad.exe $ReportFile

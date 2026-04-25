# Velveteen Hunt Pack — Quick Start

## What This Is

Velveteen Hunt Pack is a guided, read-only Windows threat hunting framework.

It walks you through:
- Finding suspicious activity
- Organizing findings
- Correlating signals
- Investigating deeper when needed

---

## Before You Start

- Run PowerShell as Administrator (recommended)
- Ensure scripts are in the same directory
- Allow script execution if needed:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

---

## Step 1 — Run the Hunt Phase

Run these scripts in order:

.\Velveteen-Hunt-LiveProcess.ps1  
.\Velveteen-Hunt-Network.ps1  
.\Velveteen-Hunt-Sentinel.ps1  
.\Velveteen-Hunt-Persistence.ps1  
.\Velveteen-Hunt-Artifact.ps1  

Each script will:
- Generate a report
- Automatically open it in Notepad
- Show findings grouped by priority

---

## Step 2 — Run Correlation

After running the hunt scripts:

.\Velveteen-Hunt-Correlation.ps1  

This script:
- Reads all previous reports
- Identifies repeated indicators
- Highlights patterns across system activity

---

## Step 3 — Investigate Findings

If something looks suspicious, run follow-up scripts:

Process investigation:  
.\Velveteen-FollowUp-ProcessTrace.ps1  

File investigation:  
.\Velveteen-FollowUp-FileTrace.ps1  

These help answer:
- What launched this?
- What did it do?
- Is it persistent?
- Is it connected to other findings?

---

## Where Reports Are Saved

All reports are stored in:

Desktop\Velveteen-Hunt-Pack-Reports

---

## How to Read Results

HIGH PRIORITY  
Strong indicators or correlated patterns → Investigate first  

MEDIUM PRIORITY  
Suspicious but incomplete signals → Correlate with other reports  

LOW CONTEXT  
Single or baseline findings → Keep for reference  

---

## How to Think During Analysis

Follow the chain:

Process → File → Network → Persistence → Correlation  

Ask:
- What executed?
- Where did it come from?
- Did it connect outward?
- Did it establish persistence?
- Does it appear in multiple reports?

---

## Important Notes

- This toolkit is read-only
- It does not:
  - Kill processes
  - Delete files
  - Quarantine anything

You are responsible for any remediation decisions.

---

## First-Time Tip

Don’t panic if you see a lot of findings.

Focus on:
1. HIGH PRIORITY first  
2. Anything repeated across reports  
3. Anything in suspicious paths (Temp, AppData, Downloads)

Patterns matter more than single alerts.

---

## Next Steps

- Re-run scripts after system changes
- Compare reports over time
- Use correlation to spot recurring behavior
- Practice identifying normal vs abnormal patterns

---

## Goal

Velveteen is not just about finding threats.

It’s about learning how to think like an analyst.

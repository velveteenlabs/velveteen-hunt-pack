# Velveteen Hunt Pack
A compact PowerShell suite for stealth malware, RAT, persistence, and C2 hunting.

## Relationship to Velveteen SOC Lite

Velveteen SOC Lite provides structured triage and high-level visibility.

Velveteen Hunt Pack extends that workflow with deeper investigation tools for:
- artifact tracing
- process lineage analysis
- persistence follow-up
- network pivoting

Use SOC Lite to identify suspicious activity, then Hunt Pack to investigate it in detail.

# Velveteen Hunt Pack

## Overview

Velveteen Hunt Pack is a **guided, read-only Windows threat hunting framework** built in PowerShell.

It is not just a collection of scripts — it is a **structured investigation workflow** designed to help analysts:

- Identify suspicious activity
- Organize findings into meaningful signals
- Correlate indicators across system layers
- Perform targeted follow-up investigations
- Preserve evidence for review or escalation

The framework emphasizes **clarity, repeatability, and analyst guidance**.

---

## Core Philosophy

Velveteen is built on a simple idea:

Most threats are not obvious — they emerge through patterns.

Instead of relying on single indicators, this toolkit helps you:

- Combine weak signals into stronger conclusions
- Understand relationships between processes, files, and network activity
- Think like an analyst, not just a scanner

---

## Key Features

- Read-only execution (no system changes)
- Phase-based investigation workflow
- Priority-based findings:
  - HIGH PRIORITY
  - MEDIUM PRIORITY
  - LOW CONTEXT
- Guided analysis embedded in every script
- Correlation across multiple reports
- Targeted follow-up investigation scripts
- Evidence-friendly output (TXT + optional HTML)

---

## Investigation Workflow

HUNT PHASE  
Velveteen-Hunt-LiveProcess.ps1  
Velveteen-Hunt-Network.ps1  
Velveteen-Hunt-Sentinel.ps1  
Velveteen-Hunt-Persistence.ps1  
Velveteen-Hunt-Artifact.ps1  

ANALYSIS PHASE  
Velveteen-Hunt-Correlation.ps1  

INVESTIGATION PHASE  
Velveteen-FollowUp-ProcessTrace.ps1  
Velveteen-FollowUp-FileTrace.ps1  

---

## Scripts Included

Velveteen-Hunt-LiveProcess.ps1  
Reviews running processes and command-line activity  

Velveteen-Hunt-Network.ps1  
Analyzes network connections and remote endpoints  

Velveteen-Hunt-Sentinel.ps1  
Reviews Defender/security telemetry context  

Velveteen-Hunt-Persistence.ps1  
Identifies startup, registry, task, and service persistence  

Velveteen-Hunt-Artifact.ps1  
Identifies suspicious files and staging locations  

Velveteen-Hunt-Correlation.ps1  
Correlates indicators across all reports  

Velveteen-FollowUp-ProcessTrace.ps1  
Deep-dives into process execution chains  

Velveteen-FollowUp-FileTrace.ps1  
Investigates file behavior and persistence references  

---

## Output Model

All scripts generate structured reports in:

Desktop\Velveteen-Hunt-Pack-Reports

Each report includes:

- Standard header
- Priority-based findings
- Analyst guidance
- Follow-up recommendations
- Evidence handling notes

---

## Priority Buckets

HIGH PRIORITY  
Strong indicators or correlated patterns suggesting meaningful risk  

MEDIUM PRIORITY  
Suspicious but incomplete signals that require correlation  

LOW CONTEXT  
Single or baseline findings retained for reference  

---

## Quick Start

Run the hunt phase:

.\Velveteen-Hunt-LiveProcess.ps1  
.\Velveteen-Hunt-Network.ps1  
.\Velveteen-Hunt-Sentinel.ps1  
.\Velveteen-Hunt-Persistence.ps1  
.\Velveteen-Hunt-Artifact.ps1  

Then run correlation:

.\Velveteen-Hunt-Correlation.ps1  

Then investigate findings:

.\Velveteen-FollowUp-ProcessTrace.ps1  
.\Velveteen-FollowUp-FileTrace.ps1  

---

## How to Use This Toolkit

Think in chains:

Process → File → Network → Persistence → Correlation  

Ask:

- What executed?
- Where did it come from?
- Did it connect outward?
- Did it establish persistence?
- Does it appear in multiple reports?

---

## Evidence Handling

- Do not delete or modify files during analysis
- Preserve timestamps and report outputs
- Record who ran scripts and when
- Hash files before remediation
- Treat correlation as analysis, not proof

---

## Safety Notes

This toolkit is read-only.

It does not:

- Kill processes
- Delete files
- Quarantine anything
- Upload data externally

You remain in control of all remediation decisions.

---

## Intended Audience

- Entry-level analysts
- Blue team practitioners
- Incident response learners
- Cybersecurity students
- Anyone learning structured threat hunting

---

## Disclaimer

This toolkit is intended for defensive security and educational use only.

Use responsibly.

---

## Final Note

Velveteen Hunt Pack is designed to teach you how to think.

Not “Is this malicious?”

But:

“What story do these signals tell together?”

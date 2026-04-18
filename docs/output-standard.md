# Velveteen Output Standard

## Purpose

This document defines how all Velveteen scripts generate output.

Velveteen is designed for:

* evidence preservation
* anomaly surfacing
* investigator-guided analysis

It does **not** attempt to:

* auto-confirm malware
* suppress data as "noise"
* replace analyst judgment

---

## Core Principles

### 1. Preserve Everything

Velveteen does **not discard findings**.

Instead:

* findings are grouped
* patterns are surfaced
* context is retained

Small signals may become critical when correlated later.

---

### 2. Priority Bucketing (Core System)

All findings are grouped into:

### HIGH PRIORITY

* strong signals
* dangerous combinations
* immediate follow-up candidates

### MEDIUM PRIORITY

* suspicious or unusual
* worth focused investigation

### LOW CONTEXT

* not immediately suspicious
* retained for correlation and timeline building

These are **not final conclusions**.

---

### 3. No Overclaiming

Velveteen avoids definitive statements like:

* "this is malware"
* "this is C2"

Instead uses:

* “suspicious”
* “may indicate”
* “requires correlation”

Example philosophy already used in scripts:

> No final conclusion is made at this stage.

---

### 4. Findings Must Explain Themselves

Every finding must include:

* **Finding** → what was observed
* **Why** → why it matters

Example:

```text
Finding: Process executable is running from a user-writable path
Why: Malware and staged loaders commonly execute from AppData, Temp, or ProgramData
```

---

### 5. Context Matters More Than Volume

Velveteen focuses on:

* combinations of signals
* relationships between process, file, network, persistence

Not:

* raw counts
* alert spam

---

## Standard Report Structure

All scripts follow this structure:

```text
============================================================
SUMMARY
============================================================

[Counts, totals, high-level overview]

============================================================
HIGH PRIORITY
============================================================

[Strong findings]

============================================================
MEDIUM PRIORITY
============================================================

[Moderate findings]

============================================================
LOW CONTEXT
============================================================

[Contextual findings]

------------------------------------------------------------

This output is an evidence artifact.
No final conclusion is made at this stage.

============================================================
ANALYST NOTES
============================================================

[Guidance + interpretation]

============================================================
FOOTER / EVIDENCE SECTION
============================================================
```

---

## Finding Object Standard

Each finding should contain:

```text
Review Priority:
Category:
Process/Object:
PID (if applicable):
Path:
Extra:

Finding:
Why:
```

This structure is already implemented in scripts.

---

## Analyst Notes Section

This section is critical.

It should:

* guide investigation
* highlight patterns to prioritize
* warn against misinterpretation

Example (aligned to your script style):

* Prioritize combinations of suspicious path, privilege, trust anomalies, and outbound connections
* LOLBin usage is not malicious by itself — evaluate context
* Timestamp anomalies are preserved for later correlation

---

## Evidence Integrity (Critical)

Every report must include:

* system evidence ID
* timestamp
* host
* SHA256 hash
* chain of custody entry
* analyst signature block

Your scripts already enforce this.

---

## Evidence Handling Guidance

All reports must instruct:

* save immediately
* copy to external SSD
* copy to secure cloud backup
* avoid leaving only on analyzed system
* preserve offline copy for high-risk findings

---

## Escalation Philosophy

If **multiple high-priority signals** exist:

* consider disk imaging
* pause further interaction
* preserve system state

Example already implemented:

> Disk imaging should be considered before continuing investigation

---

## Follow-Up Philosophy

Velveteen is modular.

Reports should recommend:

* ProcessTrace
* FileTrace
* Network Hunt
* Persistence Hunt
* Correlation

---

## Behavioral Model

Velveteen treats:

* process activity
* network activity
* file activity
* persistence
* control changes

as **connected layers**, not isolated events.

---

## Key Takeaway

Velveteen is not a scanner.

It is:

→ a **lead generation system**
→ an **evidence structuring tool**
→ an **analyst thinking assistant**

---

## Future Expansion (Optional)

Later versions may include:

* JSON sidecar output
* automated correlation ingestion
* timeline reconstruction
* multi-run comparison

Plain text remains the primary output.

# Velveteen Hunt Pack — Hunt Playbook

## Purpose

This playbook explains how to use Velveteen Hunt Pack as a structured investigation framework.

Velveteen is not designed to be a one-click malware scanner. It is designed to guide an analyst through a repeatable Windows host investigation process using read-only PowerShell scripts, structured reports, priority buckets, correlation, and targeted follow-up.

The goal is to move from scattered observations to meaningful investigative patterns.

---

## Core Investigation Model

Velveteen follows this chain:

Process → File → Network → Persistence → Correlation → Follow-Up

Each phase answers a different question:

Process:
What is running?

File:
What artifacts exist on disk?

Network:
What is communicating outward?

Persistence:
What may survive reboot?

Correlation:
What indicators repeat or connect across reports?

Follow-Up:
What needs deeper investigation?

---

## Recommended Full Workflow

Run the hunt phase first:

1. Velveteen-Hunt-LiveProcess.ps1
2. Velveteen-Hunt-Network.ps1
3. Velveteen-Hunt-Sentinel.ps1
4. Velveteen-Hunt-Persistence.ps1
5. Velveteen-Hunt-Artifact.ps1

Then run:

6. Velveteen-Hunt-Correlation.ps1

Then investigate targets with:

7. Velveteen-FollowUp-ProcessTrace.ps1
8. Velveteen-FollowUp-FileTrace.ps1

---

## Phase 1 — Live Process Hunt

Script:

Velveteen-Hunt-LiveProcess.ps1

Purpose:

This phase reviews currently running processes, executable paths, parent-child process clues, and command-line activity.

This is often the best starting point because active malware, suspicious tools, LOLBins, scripts, and remote access utilities may be visible while they are running.

What to look for:

- PowerShell with unusual command lines
- cmd.exe launching scripts or executables
- mshta.exe, wscript.exe, cscript.exe, rundll32.exe, regsvr32.exe
- Processes running from AppData, Temp, Downloads, ProgramData, or Users\Public
- Processes with missing paths
- Processes with strange parent-child relationships
- Long, encoded, obfuscated, or download-related command lines
- Unfamiliar executables using generic names like update.exe, helper.exe, service.exe, host.exe, client.exe

High concern examples:

- powershell.exe with EncodedCommand
- wscript.exe running a script from AppData
- rundll32.exe loading a DLL from Temp
- unknown.exe running from Downloads or AppData
- a user-writable executable with active network connections

Questions to ask:

- Does the process name make sense?
- Does the path make sense?
- Does the parent process make sense?
- Is the command line normal for this process?
- Is the process running from a user-writable directory?
- Does it appear elsewhere in another Velveteen report?

Pivot points:

If a process looks suspicious, run:

Velveteen-FollowUp-ProcessTrace.ps1

If the process path looks suspicious, run:

Velveteen-FollowUp-FileTrace.ps1

If the process appears with network activity, review:

Velveteen-Hunt-Network.ps1

---

## Phase 2 — Network Hunt

Script:

Velveteen-Hunt-Network.ps1

Purpose:

This phase reviews active network connections and remote endpoints.

Network findings are rarely proof by themselves. Many legitimate applications connect outward constantly. The value comes from connecting network activity to a suspicious process, suspicious file path, or suspicious command line.

What to look for:

- Unknown processes with external connections
- Repeated remote IPs
- Unusual ports
- Connections from script interpreters
- Connections from processes running in AppData, Temp, Downloads, or ProgramData
- Established connections to unfamiliar infrastructure
- Connections tied to PowerShell, rundll32, regsvr32, mshta, wscript, or cscript

High concern examples:

- powershell.exe with an established remote connection
- unknown.exe connecting outward from AppData
- rundll32.exe associated with a public IP
- repeated remote endpoint across multiple reports
- suspicious process + remote IP + persistence reference

Questions to ask:

- What process owns the connection?
- Is the process expected to make network connections?
- Is the remote endpoint repeated?
- Does the same process appear in LiveProcess?
- Does the executable path appear in Artifact or Persistence?
- Is the connection active right now, or is it historical context only?

Pivot points:

If a process owns suspicious network activity, run:

Velveteen-FollowUp-ProcessTrace.ps1

If a remote endpoint repeats across reports, run:

Velveteen-Hunt-Correlation.ps1

If packet-level review is needed, pivot to:

docs/wireshark-pivot.md

---

## Phase 3 — Sentinel / Defender Context

Script:

Velveteen-Hunt-Sentinel.ps1

Purpose:

This phase reviews local Defender/security context and security-relevant signals.

This phase helps answer whether the system has already detected, blocked, ignored, or logged suspicious activity.

What to look for:

- Disabled or weakened protection settings
- Defender exclusions
- Recent detections
- Suspicious security configuration
- Tampering clues
- Protection status that does not match expectations

High concern examples:

- Defender disabled unexpectedly
- Real-time protection disabled
- Suspicious exclusions in AppData, Temp, Downloads, ProgramData, or entire user profile paths
- Recent detection tied to a suspicious file path
- Security tool tampering combined with suspicious processes or persistence

Questions to ask:

- Is protection enabled?
- Are exclusions legitimate?
- Were there recent detections?
- Do detection paths match Artifact or Persistence findings?
- Is security visibility reduced?

Pivot points:

If a detection references a file, run:

Velveteen-FollowUp-FileTrace.ps1

If protection appears tampered with, review:

Velveteen-Hunt-Persistence.ps1
Velveteen-Hunt-Artifact.ps1

Then run:

Velveteen-Hunt-Correlation.ps1

---

## Phase 4 — Persistence Hunt

Script:

Velveteen-Hunt-Persistence.ps1

Purpose:

This phase reviews common persistence mechanisms such as startup folders, registry Run keys, scheduled tasks, and services.

Persistence is important because it shows how suspicious activity may survive reboot or user logout.

What to look for:

- Startup entries pointing to user-writable paths
- Registry Run or RunOnce entries with suspicious executables
- Scheduled tasks with strange names or actions
- Services pointing to AppData, Temp, Downloads, ProgramData, or Users\Public
- Recently created or modified tasks
- Generic names like updater, helper, service, sync, monitor, host
- Tasks or services launching PowerShell, cmd, wscript, mshta, rundll32, or regsvr32

High concern examples:

- Run key launching a file from AppData
- Scheduled task launching PowerShell with encoded command
- Service binary path pointing to Temp
- Persistence entry referencing a file also found in Artifact
- Persistence entry referencing a process that also appears in Network

Questions to ask:

- What launches at startup?
- Where does the referenced file live?
- Is the path writable by the user?
- Is the task/service name trying to look legitimate?
- Does the referenced file appear in Artifact?
- Does the referenced process appear in LiveProcess or Network?

Pivot points:

If persistence references a file, run:

Velveteen-FollowUp-FileTrace.ps1

If persistence references a process, run:

Velveteen-FollowUp-ProcessTrace.ps1

Then run:

Velveteen-Hunt-Correlation.ps1

---

## Phase 5 — Artifact Hunt

Script:

Velveteen-Hunt-Artifact.ps1

Purpose:

This phase reviews suspicious file artifacts in common staging and abuse locations.

Malware often leaves behind files, scripts, shortcuts, dropped payloads, renamed tools, or execution support files.

What to look for:

- Executables in AppData, Temp, Downloads, ProgramData, or Users\Public
- Scripts such as .ps1, .vbs, .js, .bat, .cmd
- Shortcut files pointing to suspicious targets
- Recently modified files
- Generic or deceptive filenames
- Files with suspicious extensions
- Files that match paths from process, network, or persistence reports

High concern examples:

- .exe in Temp
- .ps1 in AppData
- .lnk pointing to PowerShell
- recently modified DLL in a user-writable directory
- file path repeated in Persistence and LiveProcess
- file hash repeated across multiple reports

Questions to ask:

- What is this file?
- Why is it in this location?
- Was it modified recently?
- Is it referenced by a process?
- Is it referenced by persistence?
- Does it have a hash?
- Should the hash be reputation checked?

Pivot points:

If a suspicious file is found, run:

Velveteen-FollowUp-FileTrace.ps1

If a suspicious file is actively running, run:

Velveteen-FollowUp-ProcessTrace.ps1

Then run:

Velveteen-Hunt-Correlation.ps1

---

## Phase 6 — Correlation

Script:

Velveteen-Hunt-Correlation.ps1

Purpose:

This phase reads prior Velveteen reports and identifies repeated indicators and cross-report relationships.

Correlation is the analysis brain of the Hunt Pack. It helps turn isolated findings into possible attack chains.

What correlation looks for:

- Repeated process names
- Repeated file paths
- Repeated remote IPs
- Repeated command lines
- Repeated hashes
- File paths appearing in persistence context
- Processes appearing in network context
- Suspicious paths appearing across multiple reports
- Medium or low signals that combine into higher concern

High concern examples:

- Same suspicious process appears in LiveProcess, Network, and Persistence
- Same file path appears in Artifact and Persistence
- Remote endpoint appears repeatedly with suspicious process context
- Encoded command appears in more than one report
- File in AppData is running, connecting outward, and referenced by startup

Medium concern examples:

- Indicator appears in two reports
- Suspicious path appears once in a risky location
- Hash appears once and needs reputation checking
- Process appears in LiveProcess and Artifact but without network activity
- Persistence entry exists but file context is unclear

Low context examples:

- Single process observation
- Single file path with no other evidence
- One remote IP with no process context
- One command line without suspicious patterns

How to interpret correlation:

Correlation is not automatic proof of compromise.

Correlation means:

- This deserves analyst attention
- This may represent a pattern
- This should be investigated before remediation

Questions to ask:

- Which indicators repeat?
- Which reports did they appear in?
- Do the phases connect logically?
- Does the story make sense?
- Is this normal software behavior?
- Is there enough evidence to escalate?

Pivot points:

For suspicious process correlations, run:

Velveteen-FollowUp-ProcessTrace.ps1

For suspicious file/path correlations, run:

Velveteen-FollowUp-FileTrace.ps1

If evidence may be stale, rerun the relevant hunt phase.

---

## Phase 7 — Follow-Up Process Trace

Script:

Velveteen-FollowUp-ProcessTrace.ps1

Purpose:

This script investigates a specific suspicious process found by another phase.

Use it when:

- A process is flagged HIGH or MEDIUM
- A process owns a suspicious network connection
- A command line looks suspicious
- A process path is unusual
- A process appears in Correlation
- You need parent/child context

What it helps answer:

- What is the process?
- What launched it?
- What did it launch?
- Where is it running from?
- What command line was used?
- Does it have active network connections?
- Does the process chain make sense?

High concern examples:

- explorer.exe → powershell.exe → unknown.exe
- winword.exe → powershell.exe
- browser.exe → unknown file in AppData
- powershell.exe with encoded command
- script interpreter with remote connection
- process launched from Temp with children

Questions to ask:

- Is the parent process expected?
- Are child processes expected?
- Is the command line suspicious?
- Is the path suspicious?
- Is it communicating outward?
- Does the file need FileTrace?

Next pivot:

If the executable path is suspicious, run:

Velveteen-FollowUp-FileTrace.ps1

If the process has network connections, review:

Velveteen-Hunt-Network.ps1

If the process appears in multiple reports, review:

Velveteen-Hunt-Correlation.ps1

---

## Phase 8 — Follow-Up File Trace

Script:

Velveteen-FollowUp-FileTrace.ps1

Purpose:

This script investigates a specific suspicious file path found by another phase.

Use it when:

- Artifact finds a suspicious file
- Persistence references a file
- Correlation flags a path
- A process runs from an unusual location
- A hash needs to be preserved
- A file may be tied to startup, tasks, or services

What it helps answer:

- Does the file exist?
- Where is it located?
- What is its hash?
- When was it created or modified?
- Is it currently running?
- Is it referenced by registry startup entries?
- Is it referenced by scheduled tasks?
- Is it referenced by services?

High concern examples:

- File in AppData referenced by Run key
- File in Temp referenced by scheduled task
- File in ProgramData running as a service
- Script file referenced by startup
- Same file path appears across Artifact, Persistence, and ProcessTrace

Questions to ask:

- Is this file expected?
- Is the location suspicious?
- Is the timestamp suspicious?
- Is it currently running?
- Is it persistent?
- Does the hash appear elsewhere?
- Should the hash be reputation checked?

Next pivot:

If the file is running, run:

Velveteen-FollowUp-ProcessTrace.ps1

If the file is persistent, review:

Velveteen-Hunt-Persistence.ps1

If the file appears across reports, review:

Velveteen-Hunt-Correlation.ps1

---

## Priority Model

Velveteen uses three priority buckets.

These buckets are designed to guide analyst attention, not to replace judgment.

---

## HIGH PRIORITY

High priority findings represent strong signals, dangerous combinations, or correlated patterns.

Examples:

- Suspicious process with network activity
- Suspicious file in persistence location
- Encoded PowerShell command
- Script interpreter launching payloads
- Remote endpoint repeated across reports
- Process + file + network + persistence chain
- Defender tampering plus suspicious artifacts

How to handle:

- Review immediately
- Preserve report output
- Do not delete yet
- Run follow-up scripts
- Collect hashes and paths
- Correlate before remediation

---

## MEDIUM PRIORITY

Medium priority findings represent suspicious but incomplete signals.

Examples:

- Suspicious path without execution evidence
- Unusual scheduled task
- Recently modified executable in AppData
- Unknown process without obvious network activity
- Single suspicious command line
- Repeated indicator across two reports

How to handle:

- Validate context
- Check whether the item is expected
- Look for repetition
- Run correlation
- Use follow-up scripts if the finding persists or connects to other evidence

---

## LOW CONTEXT

Low context findings are single observations or baseline items retained for reference.

Examples:

- One process with no suspicious path or command line
- One remote IP without process context
- One file path with no persistence or execution evidence
- Normal-looking service or scheduled task

How to handle:

- Do not ignore completely
- Do not overreact
- Keep for comparison
- Revisit if it appears again
- Use as baseline material

---

## Signal Combination Guide

Single signals are often weak. Combinations matter.

Process only:
Possible normal activity. Needs more context.

Process + suspicious path:
More concerning. Check file metadata and hash.

Process + network:
Potential active communication. Check endpoint and parent process.

Process + persistence:
Potential durable execution. Check file path and startup mechanism.

File + persistence:
High concern if file is in AppData, Temp, Downloads, ProgramData, or Users\Public.

File + network:
High concern if the file is unknown, recently modified, or user-writable.

Command line + encoded/download behavior:
High concern, especially with PowerShell, cmd, mshta, wscript, cscript, rundll32, or regsvr32.

Remote IP + suspicious process:
High concern if the process should not normally connect outward.

Repeated indicator across three or more reports:
High concern. Investigate first.

---

## Common Suspicious Locations

These locations are not automatically malicious, but they are commonly abused:

C:\Users\<User>\AppData\Local\Temp
C:\Users\<User>\AppData\Roaming
C:\Users\<User>\Downloads
C:\ProgramData
C:\Users\Public
Startup folders
Unusual folders under user profile paths

Why they matter:

- Users and malware can usually write there
- Payloads are often staged there
- Scripts and droppers may run from there
- Persistence may point back to these locations

---

## Common Living-Off-the-Land Processes

These Windows-native tools can be legitimate, but they are also commonly abused.

PowerShell:
Can execute scripts, download payloads, run encoded commands, and automate attacker actions.

cmd.exe:
Can launch scripts, commands, batch files, and other tools.

wscript.exe / cscript.exe:
Can run VBScript or JScript.

mshta.exe:
Can execute HTML applications and script content.

rundll32.exe:
Can execute DLL-based payloads.

regsvr32.exe:
Can load or register DLLs and has been abused for scriptlet execution.

bitsadmin.exe:
Can transfer files.

certutil.exe:
Can download or decode content.

schtasks.exe:
Can create or modify scheduled tasks.

reg.exe:
Can modify registry persistence.

What to ask:

- Is this process expected?
- What launched it?
- What command line did it use?
- Is it touching files in suspicious paths?
- Is it connecting outward?
- Is it creating persistence?

---

## Command Line Red Flags

Look closer when command lines include:

EncodedCommand
FromBase64String
Invoke-Expression
IEX
DownloadString
WebClient
curl
wget
bitsadmin
mshta
regsvr32
rundll32
wscript
cscript
-NoProfile
-ExecutionPolicy Bypass
-WindowStyle Hidden
Hidden
base64-looking strings
long unreadable strings
URLs
IP addresses
Temp or AppData paths

Interpretation:

One suspicious command does not prove compromise, but it deserves follow-up.

A suspicious command plus suspicious path, network connection, or persistence is much stronger.

---

## Persistence Red Flags

Look closer when persistence points to:

- AppData
- Temp
- Downloads
- ProgramData
- Users\Public
- PowerShell commands
- Script files
- Generic updater names
- Random-looking filenames
- Recently modified binaries
- Missing or quoted/unquoted strange paths

Common persistence mechanisms:

Registry Run keys
Registry RunOnce keys
Scheduled tasks
Services
Startup folders
WMI subscriptions
Browser extensions
Logon scripts

Velveteen focuses on common beginner-visible persistence areas. Advanced persistence may require additional tooling.

---

## Network Red Flags

Look closer when:

- A script interpreter owns a connection
- An unknown process connects outward
- A process from AppData or Temp connects outward
- The same IP repeats
- Connections appear during suspicious process execution
- Remote endpoint appears in multiple reports
- Connection uses unusual ports
- Process path is missing or strange

Do not assume every foreign IP is malicious.

Many legitimate services use cloud hosting, CDNs, VPNs, and rotating infrastructure.

Always connect network evidence back to process and file context.

---

## Artifact Red Flags

Look closer when files are:

- Recently modified
- Executable or script-based
- In user-writable paths
- Named generically
- Referenced by persistence
- Referenced by running processes
- Associated with suspicious command lines
- Repeated across reports

File extensions to review carefully:

.exe
.dll
.ps1
.bat
.cmd
.vbs
.js
.jse
.lnk
hta
scr

---

## Suggested Investigation Scenarios

Scenario 1:
LiveProcess finds powershell.exe with EncodedCommand.

Action:
Run ProcessTrace.
Check parent process.
Check child processes.
Check command line.
Review Network.
Run Correlation.

Concern level:
Usually high, especially if network or file artifacts are present.

---

Scenario 2:
Artifact finds update.exe in AppData.

Action:
Run FileTrace on the path.
Check hash.
Check whether it is running.
Check persistence.
Run Correlation.

Concern level:
Medium to high depending on persistence or execution evidence.

---

Scenario 3:
Network finds unknown process connecting to remote IP.

Action:
Run ProcessTrace on the process.
Check executable path.
Check parent process.
Check command line.
Run FileTrace on executable path.
Run Correlation.

Concern level:
Depends on process identity and path.

---

Scenario 4:
Persistence finds scheduled task launching a file in Temp.

Action:
Run FileTrace on referenced file.
Check task name and action.
Check whether file still exists.
Run Correlation.

Concern level:
High.

---

Scenario 5:
Correlation shows same file path in Artifact, Persistence, and ProcessTrace.

Action:
Preserve reports.
Hash file.
Run FileTrace.
Review process/network context.
Do not delete until evidence is captured.

Concern level:
High.

---

Scenario 6:
Sentinel finds Defender exclusions for AppData.

Action:
Review exclusion path.
Check Artifact for files in that path.
Check Persistence for startup references.
Run Correlation.

Concern level:
Medium to high depending on what is excluded.

---

## Evidence Handling Workflow

Velveteen is read-only, but evidence handling still matters.

Recommended process:

1. Run scripts without modifying the system.
2. Save generated reports.
3. Take screenshots of important findings if needed.
4. Hash suspicious files before remediation.
5. Record who ran scripts and when.
6. Keep raw reports separate from analyst notes.
7. Copy the full report folder before making changes.
8. Do not delete files until investigation is complete.

Reports are stored in:

Desktop\Velveteen-Hunt-Pack-Reports

Recommended preservation:

- Copy the entire report folder to external storage
- Zip the folder after investigation
- Record the date and analyst name
- Preserve suspicious file hashes
- Keep original timestamps where possible

---

## What Velveteen Does Not Do

Velveteen does not:

- Prove compromise by itself
- Replace EDR
- Replace forensic imaging
- Replace packet capture
- Replace memory forensics
- Automatically classify malware
- Delete files
- Kill processes
- Quarantine artifacts
- Upload samples
- Perform remediation

Velveteen helps structure investigation and analyst reasoning.

---

## When to Escalate

Escalate or seek expert review when:

- Multiple high priority findings appear
- Persistence is confirmed
- Suspicious process has external network activity
- Defender/security tooling appears tampered with
- Unknown files are running from AppData, Temp, or ProgramData
- Encoded commands are present
- Evidence suggests credential theft
- Evidence suggests lateral movement
- Findings involve sensitive systems, business systems, or legal concerns

---

## Analyst Mindset

Do not chase every single weird thing.

Instead, ask:

- What repeats?
- What connects?
- What changed?
- What survives reboot?
- What communicates outward?
- What lacks a legitimate explanation?
- What appears in more than one phase?

Good analysis is pattern recognition with restraint.

Velveteen is designed to help you slow down, preserve evidence, and build a defensible story from the data.

---

## Final Investigation Pattern

A strong Velveteen finding usually looks like this:

A suspicious process was observed.
It launched from a suspicious file path.
The file was recently modified.
The process connected to a remote endpoint.
A persistence mechanism referenced the same file.
Correlation confirmed the indicator across multiple reports.
Follow-up scripts preserved process and file context.

That is the kind of chain that turns scattered findings into a meaningful investigation.

---

## Final Note

Velveteen Hunt Pack is built to teach structured threat hunting.

The goal is not to panic over every artifact.

The goal is to understand what the system is telling you.

Patterns matter.

Context matters.

Correlation matters.

The story matters.

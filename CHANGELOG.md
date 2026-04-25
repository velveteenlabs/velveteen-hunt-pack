# Changelog

All notable changes to Velveteen Hunt Pack will be documented in this file.

The format is inspired by Keep a Changelog principles.


## [1.0.0] - Initial Release

### Added

Core Hunt Framework:

- Velveteen-Hunt-LiveProcess.ps1  
  Reviews active processes, command lines, and execution context

- Velveteen-Hunt-Network.ps1  
  Analyzes active network connections and remote endpoints

- Velveteen-Hunt-Sentinel.ps1  
  Reviews Defender/security posture and telemetry context

- Velveteen-Hunt-Persistence.ps1  
  Identifies startup mechanisms including registry, tasks, and services

- Velveteen-Hunt-Artifact.ps1  
  Detects suspicious files in common staging and user-writable locations


Analysis Layer:

- Velveteen-Hunt-Correlation.ps1  
  Correlates indicators across all Velveteen reports  
  Promotes repeated and cross-phase signals into higher priority findings  
  Generates both TXT and HTML reports


Follow-Up Investigation Tools:

- Velveteen-FollowUp-ProcessTrace.ps1  
  Deep investigation of process execution chains  
  Includes parent/child relationships, command line, and network context  

- Velveteen-FollowUp-FileTrace.ps1  
  Deep investigation of file artifacts  
  Includes hash generation, persistence checks, and execution references  


Framework Features:

- Structured investigation workflow (Hunt → Analysis → Follow-Up)
- Priority-based findings model:
  - HIGH PRIORITY
  - MEDIUM PRIORITY
  - LOW CONTEXT
- Read-only execution model (no system modification)
- Auto-generated and auto-opened TXT reports
- Optional HTML report generation for correlation phase
- Consistent report structure across all scripts
- Embedded analyst guidance in every script
- Evidence and chain-of-custody awareness built into outputs


Documentation:

- README.md  
  Overview, workflow, and usage instructions

- docs/quick-start.md  
  Beginner-friendly first-run guide

- docs/hunt-playbook.md  
  Full investigation methodology and phase-by-phase guidance

- docs/stealth-malware-hunting.md  
  Guide to identifying low-signal and stealthy threats

- docs/wireshark-pivot.md  
  Guide for pivoting from Velveteen findings into packet analysis


Supporting Assets:

- samples/Velveteen-Sample-Report.txt  
  Example output demonstrating structure and analysis style

- templates/Velveteen-Script-Header-Template.txt  
  Standardized script header format

- templates/Velveteen-Report-Template.txt  
  Standardized report structure

- templates/Velveteen-Footer-Template.txt  
  Evidence handling and chain-of-custody template


### Notes

Velveteen Hunt Pack is designed as a guided investigation framework rather than an automated detection tool.

It emphasizes:
- pattern recognition over single indicators
- structured analysis over raw output
- correlation over assumption

This release establishes the full baseline system.


## Future Considerations

- Expanded persistence detection coverage
- Optional hashing and reputation integration
- Timeline reconstruction features
- Memory and advanced artifact extensions
- Optional export formats and report bundling

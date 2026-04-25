# Wireshark Pivot Guide

## Purpose

This guide explains how to pivot from Velveteen Hunt Pack findings into deeper network analysis using Wireshark.

Velveteen identifies suspicious network behavior at a high level.

Wireshark allows you to:

- Inspect packet-level activity
- Validate connections
- Analyze protocols
- Identify data exfiltration or command-and-control behavior

---

## When to Pivot to Wireshark

Use Wireshark when Velveteen shows:

- Suspicious remote IPs
- Unknown processes making connections
- Repeated endpoints across reports
- Unusual ports
- Script interpreters with network activity
- Correlation showing process + network patterns

---

## Key Question

Velveteen tells you:

"This process is connecting outward."

Wireshark helps answer:

"What is actually being sent and received?"

---

## Basic Setup

1. Install Wireshark
2. Run as Administrator
3. Select active network interface
4. Start capture

---

## Capture Strategy

### Short Capture

Use when:

- Investigating active behavior
- Following up on a known suspicious process

---

### Longer Capture

Use when:

- Watching for beaconing behavior
- Looking for periodic connections

---

## Mapping Velveteen → Wireshark

From Velveteen Network report, identify:

- Process name
- PID (if available)
- Remote IP
- Remote port

In Wireshark, filter using:

ip.addr == <REMOTE_IP>

Example:

ip.addr == 192.168.1.50

---

## Useful Filters

Basic:

ip.addr == x.x.x.x

By port:

tcp.port == 443  
tcp.port == 80  
udp.port == 53  

By protocol:

dns  
http  
tls  

By direction:

ip.src == x.x.x.x  
ip.dst == x.x.x.x  

---

## What to Look For

### Repeated Connections

- Same IP contacted repeatedly
- Regular intervals (beaconing behavior)

---

### DNS Queries

- Unusual domains
- Random-looking domain names
- High volume of queries

---

### HTTP Traffic

- Cleartext requests
- Suspicious URLs
- File downloads

---

### TLS Traffic

- Encrypted connections
- Look for:
  - Server Name Indication (SNI)
  - Certificate details

---

### Data Patterns

- Repeated small packets (beaconing)
- Large outbound transfers (exfiltration)
- Irregular traffic patterns

---

## Correlation Back to Velveteen

Always map findings back:

Wireshark → Velveteen → System context

Ask:

- Which process owns this traffic?
- Does that process appear in LiveProcess?
- Does its path appear in Artifact?
- Is it persistent?
- Does Correlation show repetition?

---

## Example Pivot

Velveteen shows:

- powershell.exe
- remote IP 45.XX.XX.XX

Wireshark:

- Filter ip.addr == 45.XX.XX.XX
- Observe:
  - connection frequency
  - packet size
  - protocol used

Then:

- Return to ProcessTrace
- Investigate command line
- Investigate file path

---

## Common Patterns

### Beaconing

- Small packets
- Regular intervals
- Same destination

---

### Download Activity

- Large inbound data
- HTTP or HTTPS
- Followed by process execution

---

### Exfiltration

- Large outbound data
- Unusual destinations
- Repeated transfers

---

## Limitations

Wireshark cannot:

- Identify malware automatically
- Always decrypt encrypted traffic
- Tell you which process generated traffic (without correlation)

Velveteen provides that missing context.

---

## Best Practice

Always combine:

Velveteen findings  
+  
Wireshark analysis  

Never rely on one alone.

---

## Final Workflow

1. Identify suspicious connection in Velveteen
2. Capture traffic in Wireshark
3. Filter by IP/port
4. Analyze behavior
5. Map back to process/file
6. Run follow-up scripts
7. Correlate findings

---

## Final Note

Velveteen tells you:

"Something is happening."

Wireshark tells you:

"What exactly is happening."

Together, they give you full visibility.

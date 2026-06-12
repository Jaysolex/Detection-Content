# CHM File Execution — Advanced Detection Guide
## APT-Grade Detection for Weaponized Help File Attacks

**MITRE ATT&CK:** T1218.001 — System Binary Proxy Execution: Compiled HTML File
**Secondary:** T1566.001 (Spearphishing), T1204.002 (Malicious File), T1547.001 (Registry Run Keys), T1053.005 (Scheduled Task)
**Tactics:** Initial Access | Execution | Defense Evasion | Persistence
**Detection Rule:** #25 — Advanced (upgrades Rule #22)
**Severity:** Critical
**Author:** Solomon James
**Last Updated:** June 2026

---

## Executive Summary

CHM (Compiled HTML Help) file attacks are a proven, multi-year initial access technique actively used by nation-state APT groups and cybercriminal organizations. The attack abuses `hh.exe` — a **signed, trusted Microsoft binary present on every Windows installation** — to execute embedded scripts that bypass email gateways, antivirus, and Device Guard on unpatched systems.

**Confirmed APT groups using CHM delivery (active through 2025):**

| Threat Actor | Region | Notable CHM Campaign | Key TTP |
|---|---|---|---|
| **APT41** | China | Dual espionage + cybercrime ops | wmic.exe, schtasks, Cobalt Strike via cmd |
| **APT37 (Reaper)** | North Korea | FadeStealer campaign | PowerShell autostart backdoor |
| **Kimsuky (APT43)** | North Korea | DEEP#GOSU 2024, ongoing 2025 | reg.exe Run key, Base64 VBScript, ISO/ZIP delivery |
| **Bitter APT** | South Asia | Active through Q3 2025 | CHM first-stage, remote C2 stage-2 download |
| **Silence APT** | Russia | Financial sector targeting | bitsadmin download cradle, email bypass |
| **DeathStalker** | Unknown | Spearphishing campaigns | CHM email delivery, script execution |

**Without real-time detection, the typical attack timeline is:**

```
T+0:00   User opens CHM file (disguised as invoice, help doc, or password sheet)
T+0:02   hh.exe spawns child process (PowerShell, wmic, reg.exe)
T+0:05   Stage 2 payload downloaded (Cobalt Strike beacon, RAT, backdoor)
T+0:30   C2 channel established — attacker has interactive access
T+1:00   Credential harvesting begins (LSASS dump, keylogging)
T+4:00   Lateral movement to domain controllers or high-value targets
T+24:00  Ransomware deployed OR data exfiltrated silently
```

**Rule #25 fires at T+0:02 — before any downstream damage occurs.**

---

## Why CHM Bypasses Your Defenses

| Defense Layer | Why CHM Bypasses It |
|---|---|
| **Email Gateway** | `.chm` not flagged as executable by most filters. Kimsuky wraps CHM in ISO/ZIP/VHD to bypass even `.chm` blocks |
| **Antivirus (Signature)** | Compiled format obscures embedded scripts from signature scanning |
| **Application Whitelisting** | `hh.exe` is signed by Microsoft — it passes most whitelist policies |
| **Device Guard / UMCI** | On unpatched systems, CHM bypasses UMCI via Internet Explorer components loaded by hh.exe |
| **User Suspicion** | Files named `password.chm`, `invoice_help.chm`, or `Q2_report.chm` look legitimate |
| **EDR Behavioral** | Many EDR solutions don't flag `hh.exe` by default due to low prevalence and legacy status |

---

## Real-World APT Techniques Detected by Rule #25

### Kimsuky — Registry Persistence via reg.exe
```
hh.exe opens malicious CHM
    └── Embedded JavaScript/ActiveX executes
            └── hh.exe spawns reg.exe
                    └── reg.exe ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
                                /v SystemHelper /t REG_SZ
                                /d "wscript.exe C:\Users\<user>\AppData\Roaming\helper.vbs"
                    └── Base64-obfuscated VBScript installed for persistence
                    └── Executes on every user login — establishes C2 callback
```
**Detected by:** `selection_persistence` (reg.exe child) + `registry_persistence` flag (Run key in CommandLine)

---

### APT41 — WMI Execution + Scheduled Task
```
hh.exe opens CHM (delivered via spearphishing)
    └── hh.exe spawns wmic.exe
            └── wmic process call create "cmd /c schtasks /create ..."
                    └── Scheduled task executes Cobalt Strike stager
                    └── Beacon phones home on HTTPS — blends with normal traffic
```
**Detected by:** `selection_wmi` (wmic child, risk score 95) + `selection_persistence` (schtasks)

---

### APT37 — PowerShell Autostart Backdoor
```
User opens "password.chm" (sent with malicious document)
    └── CHM displays fake password to social engineer compliance
    └── hh.exe silently spawns powershell.exe
            └── PowerShell downloads backdoor from C2
            └── Registers autostart via reg.exe Run key
            └── Backdoor communicates with C2 for command execution
```
**Detected by:** `selection_scripting` (powershell child, risk score 85) + encoded payload flag

---

### Kimsuky — Container Delivery (ISO/ZIP/VHD Wrapping)
```
Phishing email → ZIP attachment containing CHM file
    └── User extracts ZIP → double-clicks CHM
            └── hh.exe executes from %TEMP% or Downloads path
                    └── Embedded VBScript runs
                    └── Connects to gosiweb.gosiclass[.]com (documented C2)
```
**Detected by:** `selection_container_delivery` (suspicious path in ParentCommandLine) + `CHMNetworkConnections`

---

### Bitter APT — CHM First-Stage Remote Download
```
CHM file delivered as spearphishing attachment (active 2023-2025)
    └── hh.exe opens CHM
            └── Malicious script connects to remote server
            └── Downloads and executes backdoor module
            └── Only delivers final payload to pre-authorized system configs
```
**Detected by:** `selection_network` (hh.exe DNS/network Event ID 3/22) + `CHMNetworkConnections` (port detection)

---

### Silence APT / DeathStalker — Email Bypass via CHM
```
CHM file sent directly as email attachment (bypasses .exe/.doc filters)
    └── hh.exe spawns bitsadmin.exe or certutil.exe
            └── Background download of secondary payload
            └── No visible window — fully silent execution
```
**Detected by:** `selection_download_cradles` (bitsadmin/certutil child, risk score 90)

---

## Detection Coverage Map

| Child Process | Risk Score | APT Group | Technique |
|---|---|---|---|
| `mshta.exe` | 95 | Multiple | LOLBIN proxy chain |
| `wmic.exe` | 95 | APT41 | WMI execution |
| `certutil.exe` | 90 | APT41, Silence | Download cradle |
| `bitsadmin.exe` | 90 | Silence, DeathStalker | Background download |
| `msiexec.exe` | 90 | Multiple | MSI payload execution |
| `regsvr32.exe` | 88 | Multiple | DLL proxy execution |
| `schtasks.exe` | 88 | APT41, Kimsuky | Scheduled task persistence |
| `reg.exe` | 85 | Kimsuky | Registry Run key persistence |
| `powershell.exe` | 85 | APT37, Kimsuky | Backdoor download/exec |
| `rundll32.exe` | 80 | Multiple | DLL side-loading |
| `wscript.exe` | 75 | Kimsuky | VBScript execution |
| `cscript.exe` | 75 | Multiple | JScript/VBScript console |
| `cmd.exe` | 70 | APT41, APT37 | Command chaining |
| Network (hh.exe) | 95 | Kimsuky, Bitter APT | C2 callback / stage-2 |

---

## Sigma Rule

```yaml
title: Advanced CHM File Execution - APT-Grade Detection
id: 00000025-0000-0000-0000-000000000025
status: production
description: Detects weaponized CHM files with full APT TTP coverage
author: Solomon James
date: 2026/06/12
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1204.002
  - attack.defense_evasion
  - attack.t1218.001
  - attack.persistence
  - attack.t1547.001
  - attack.t1053.005
logsource:
  category: process_creation
  product: windows
detection:
  selection_scripting:
    ParentImage|endswith: '\hh.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  selection_download_cradles:
    ParentImage|endswith: '\hh.exe'
    Image|endswith:
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\regsvr32.exe'
      - '\rundll32.exe'
      - '\msiexec.exe'
  selection_persistence:
    ParentImage|endswith: '\hh.exe'
    Image|endswith:
      - '\reg.exe'
      - '\regini.exe'
      - '\schtasks.exe'
      - '\at.exe'
  selection_wmi:
    ParentImage|endswith: '\hh.exe'
    Image|endswith:
      - '\wmic.exe'
      - '\wmiprvse.exe'
  selection_network:
    Image|endswith: '\hh.exe'
    EventID:
      - 3
      - 22
  selection_container_delivery:
    ParentImage|endswith: '\hh.exe'
    ParentCommandLine|contains:
      - '.iso'
      - '.vhd'
      - '.zip'
      - '.rar'
      - 'AppData\Local\Temp'
      - 'Downloads'
      - 'Users\Public'
  condition: >
    selection_scripting or selection_download_cradles or
    selection_persistence or selection_wmi or
    selection_network or selection_container_delivery
falsepositives:
  - Legacy enterprise CHM help systems (whitelist by full ParentCommandLine path only)
  - Software vendor documentation tools (validate against approved software inventory)
level: high
```

---

## Chainsaw Validation

```bash
# Validate against Example7 EVTX logs
chainsaw hunt /path/to/Example7/ \
  -s myrules/25_chm_advanced_execution.yml \
  --mapping mappings/sigma-event-logs-all.yml --full

# Export as JSON for SIEM import
chainsaw hunt /path/to/Example7/ \
  -s myrules/25_chm_advanced_execution.yml \
  --mapping mappings/sigma-event-logs-all.yml \
  --json > chm_rule25_results.json
```

---

## SOC Investigation Playbook

```
ALERT: Rule #25 fires — hh.exe spawned [child process]
│
├── IMMEDIATE (0-5 min)
│     ├── Is the alert in the FP whitelist? → If no, treat as confirmed
│     ├── What is the child process? → Check risk score table above
│     ├── Is the host a DC, file server, or finance system? → P1 if yes
│     └── Is the user a privileged account (admin, DA, SA)? → Escalate immediately
│
├── TRIAGE (5-15 min)
│     ├── Pull full CommandLine:
│     │     ├── Base64 encoded? → Stage 2 already running, escalate NOW
│     │     ├── URL present? → Threat intel pivot on domain/IP
│     │     └── Run key / schtasks? → Persistence established, scope the damage
│     ├── Pull ParentCommandLine:
│     │     └── CHM path → Preserve as forensic evidence
│     ├── Check email gateway:
│     │     └── How was the CHM delivered? ISO/ZIP? Direct attachment?
│     └── Check Sysmon Event ID 3: Is hh.exe calling out to the internet?
│
├── CONTAINMENT (15-30 min) — if malicious confirmed
│     ├── Isolate host via EDR quarantine
│     ├── Disable user AD account temporarily
│     ├── Block destination IP/domain at firewall + proxy
│     └── Preserve: memory dump, EVTX logs, CHM file, network PCAP
│
├── ESCALATION TRIGGERS
│     ├── RiskScore >= 90 → IR team, P1 incident
│     ├── EncodedPayload = YES → Assume compromise, memory dump now
│     ├── RegistryPersistence = YES → Scope all Run keys on host
│     ├── WMI/schtasks child → APT41 profile — check for Cobalt Strike
│     └── Multiple hosts affected → Declare major incident
│
└── FOLLOW-ON HUNTS
      ├── Lateral movement: Event ID 4624 (same user, other hosts)
      ├── Scheduled tasks: DeviceEvents where ActionType == ScheduledTaskCreated
      ├── Registry Run keys: DeviceRegistryEvents where RegistryKey contains "Run"
      └── C2 traffic: DeviceNetworkEvents where InitiatingProcessFileName == "hh.exe"
```

---

## False Positive Management

| Scenario | Correct Mitigation |
|---|---|
| Legacy SAP / Oracle CHM help | Whitelist exact `ParentCommandLine` path — never suppress by Image alone |
| Vendor installer CHM wizard | Suppress by `ComputerName` during maintenance window only |
| IT admin CHM-based tools | Document in CMDB, create time-boxed suppression tied to change ticket |

**Critical rule:** Never create a broad suppression of `hh.exe → cmd.exe`. Always whitelist by the full, verified CHM file path. A generic suppression creates a permanent detection blind spot that APTs will exploit.

---

## Business Impact Statement

> "This rule provides real-time detection of one of the most persistent and reliable initial access techniques in the APT toolkit. CHM delivery is engineered to bypass every perimeter control — email gateways pass it, antivirus misses it, application whitelisting allows it, and users trust it. The six APT groups covered by this rule include some of the most sophisticated and well-resourced threat actors currently active globally, representing nation-state interests from China, North Korea, Russia, and South Asia. Detection at the process execution layer — before C2 establishment, before credential theft, before lateral movement — is the most cost-effective intervention point in this attack chain. A 15-minute response to a risk score 90+ alert from this rule routinely prevents incidents that would otherwise result in full domain compromise or ransomware deployment."

---

## Interview-Ready Answer

**Q: "How would you build a detection for CHM-based APT attacks?"**

> "CHM attacks are a great example of a technique that requires layered detection because the delivery and execution are specifically designed to bypass standard controls. My approach covers four layers. First, parent-child process relationships — hh.exe spawning any script interpreter or download utility is the primary signal, and I build a prioritized list based on real APT TTPs: wmic.exe and mshta.exe get a risk score of 95 because they're used in APT41's WMI execution chain and LOLBIN proxy techniques respectively; certutil and bitsadmin score 90 as download cradles used by Silence APT; reg.exe scores 85 because Kimsuky uses it to write Base64-obfuscated VBScript to registry Run keys for persistence. Second, I detect network connections and DNS queries from hh.exe directly, which catches Kimsuky's C2 callbacks and Bitter APT's stage-2 downloads. Third, I flag container delivery by checking if the CHM file path contains temp, downloads, or a container extension like ISO or ZIP — that's Kimsuky's specific technique to bypass even .chm email filters. Fourth, I scan command lines for Base64 encoding patterns, because Kimsuky specifically obfuscates their VBScript payloads. In Sentinel I union the process events with network events in a single query so the analyst gets one unified view. The response priority is simple: risk score 90 or higher with an encoded payload means I assume stage 2 is already running and I'm pulling a memory dump before I do anything else."

---

## MITRE ATT&CK Mapping

| Technique | ID | APT Group | Detection Layer |
|---|---|---|---|
| Spearphishing Attachment | T1566.001 | All | Email gateway + container delivery flag |
| Malicious File | T1204.002 | All | User execution trigger |
| Compiled HTML File | T1218.001 | All | hh.exe parent detection |
| PowerShell | T1059.001 | APT37, Kimsuky | Child process (score 85) |
| Windows Command Shell | T1059.003 | APT41 | Child process (score 70) |
| Windows Script Host | T1059.005 | Kimsuky | Child process (score 75) |
| WMI | T1047 | APT41 | Child process (score 95) |
| Ingress Tool Transfer | T1105 | Multiple | certutil/bitsadmin (score 90) |
| Registry Run Keys | T1547.001 | Kimsuky | reg.exe child + Run key flag |
| Scheduled Task | T1053.005 | APT41, Kimsuky | schtasks child (score 88) |
| System Binary Proxy Exec | T1218 | Multiple | regsvr32/rundll32/msiexec |

---

*Part of the Detection-Content framework by Solomon James | github.com/Jaysolex/Detection-Content*
*Rule #25 — APT-grade upgrade based on JustHacking.com course + real-world threat intelligence*
*Threat intel sources: MITRE ATT&CK, Rapid7, Kaspersky Securelist, Google Cloud Threat Intel, Picus Security*

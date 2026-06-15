# Windows Services — Detection Guide
## Detecting Malicious Service Creation for Continuous Persistence

**MITRE ATT&CK:** T1543.003 — Create or Modify System Process: Windows Service
**Tactics:** Persistence | Privilege Escalation
**Detection Rules:** #28 (Event ID 4697), #28b (sc.exe fallback)
**Severity:** High
**Author:** Solomon James
**Last Updated:** June 2026

---

## Executive Summary

Windows Services are the most reliable persistence mechanism available to attackers on Windows. Unlike scheduled tasks that run at intervals, services run **continuously** — starting at boot, running as SYSTEM, and operating entirely invisible to users. After gaining initial access through phishing, ISO delivery, or CHM abuse, attackers register their malware as a service to guarantee re-entry after every reboot.

**Service vs Scheduled Task — quick distinction:**

| Feature | Service | Scheduled Task |
|---|---|---|
| Think of it as | Heartbeat — runs continuously | Alarm clock — runs at trigger |
| Start behavior | Boot, automatic | Time or event triggered |
| Privilege | Often SYSTEM | Varies |
| Managed by | Service Control Manager (SCM) | Task Scheduler |
| Persistence type | Continuous | Triggered |

---

## Real Attack Chain from Lab

From the Example8 lab logs — confirmed attack sequence:

```
2024-04-09 05:32:33  Sysmon Event ID 1 (FALLBACK detection fires)
  Image:       C:\Windows\System32\sc.exe
  CommandLine: sc create Rock binPath=.\Example8.exe
  Parent:      cmd.exe
  User:        DESKTOP-0U8V16R\user
  Integrity:   High

          ↓ 27 seconds later ↓

2024-04-09 05:33:00  Security Event ID 4697 (PRIMARY detection fires)
  ServiceName:     Rock
  ServiceFileName: .\Example8.exe
  ServiceAccount:  LocalSystem
  SubjectUserName: user
  StartType:       3 (Manual)
```

Also detected on 2024-04-08: `sc create loky binPath=.\Example8.exe` — same technique, different service name.

**Why "Rock" is confirmed malicious:**
- Random service name (Windows services have descriptive names)
- Created by standard `user` account (not SYSTEM or Administrator)
- Runs as `LocalSystem` (highest local privilege — attacker gets SYSTEM)
- Executable path `.\Example8.exe` — unknown binary, no vendor signature
- Created from cmd.exe without a change management context

---

## Two Detection Methods — Defense in Depth

### Method 1 — Event ID 4697 (Primary, Gold Standard)

**What:** Security log event generated when a service is successfully installed.
**Requires:** `Audit Security System Extension` enabled in Local Security Policy.
**Path:** `secpol.msc → Advanced Audit Policy → System Audit Policies → Audit Security System Extension → Enable: Success`

**Key fields in Event ID 4697:**

| Field | What It Tells You |
|---|---|
| `ServiceName` | The name of the service (is it known?) |
| `ServiceFileName` | The executable the service runs (is it signed?) |
| `ServiceAccount` | Privilege level (LocalSystem = highest) |
| `ServiceStartType` | 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled |
| `SubjectUserName` | Who created it (standard user = red flag) |

**Limitation:** If auditing is not enabled — no log, no detection. Many organizations don't enable this by default.

### Method 2 — sc.exe + Sysmon Event ID 1 (Fallback)

**What:** Process creation event for sc.exe with `create` in the CommandLine.
**Requires:** Sysmon with process creation logging (Event ID 1).
**Why not just hunt sc.exe?** Too many false positives — `sc query`, `sc stop`, `sc start`, `sc config` are all legitimate daily admin tasks. The `create` parameter specifically identifies service registration.

**From the lab:** The Sysmon fallback fired at 05:32:33 — 27 seconds **before** Event ID 4697 confirmed the installation at 05:33:00. Together they tell the complete story: attempt → confirmation.

**Detection Engineering Principle:** Never rely on a single log source. Primary = 4697. Fallback = sc.exe create. If one fails, the other still catches it.

---

## Sigma Rules

### Rule 28 — Event ID 4697 (Primary)
```yaml
title: Suspicious Windows Service Creation
id: 00000028-0000-0000-0000-000000000028
logsource:
  product: windows
  service: security
detection:
  selection_4697:
    EventID: 4697
  condition: selection_4697
level: high
```

### Rule 28b — sc.exe Fallback (Sysmon)
```yaml
title: Service Creation via sc.exe - Sysmon Fallback
id: 00000028-0000-0000-0001-000000000028
logsource:
  category: process_creation
  product: windows
detection:
  selection_sc_create:
    EventID: 1
    Image|endswith: '\sc.exe'
    CommandLine|contains: 'create'
  condition: selection_sc_create
level: high
```

---

## Risk Scoring

| Score | Condition | Action |
|---|---|---|
| 98 | 4697 + LocalSystem + writable path | Isolate host immediately |
| 95 | 4697 + writable path payload | Sandbox executable, disable service |
| 92 | sc.exe from script host parent (PS/mshta/wscript) | High priority investigation |
| 85 | Any 4697 event | Review and validate |
| 75 | sc.exe create detected (Sysmon only) | Investigate + correlate with 4697 |

---

## Chainsaw Validation

```bash
# Detect via Event ID 4697 (Security log)
chainsaw hunt /path/to/Example8/ \
  -s myrules/28_malicious_service_creation.yml \
  --mapping mappings/sigma-event-logs-all.yml --full

# Detect via sc.exe (Sysmon fallback)
chainsaw hunt /path/to/Example8/ \
  -s myrules/28b_service_creation_sysmon_fallback.yml \
  --mapping mappings/sigma-event-logs-all.yml --full

# Expected: Both rules fire on the same attack — 4697 and sc.exe create
```

---

## SOC Investigation Playbook

```
ALERT: Service creation detected (4697 or sc.exe create)
│
├── IMMEDIATE (0-5 min)
│     ├── What is the service name? → Known software or random?
│     ├── What executable does it run? → Known path or writable location?
│     ├── Who created it? → SYSTEM/Admin (normal) or standard user (suspicious)?
│     └── What privilege does it run as? → LocalSystem = highest risk
│
├── TRIAGE (5-15 min)
│     ├── Hash the ServiceFileName → VirusTotal / sandbox analysis
│     ├── Check if service already executed:
│     │     └── System Event ID 7045 (Service installed) + 7036 (Service state change)
│     ├── Trace creator: what spawned cmd.exe or sc.exe?
│     │     └── Initial access vector (LNK? ISO? CHM? Phishing?)
│     └── Check for additional persistence: Run keys, scheduled tasks
│
├── CONTAINMENT (15-30 min) — if malicious confirmed
│     ├── Stop service: sc stop [ServiceName]
│     ├── Delete service: sc delete [ServiceName]
│     ├── Delete or quarantine payload file
│     ├── Isolate host if service already executed
│     └── Block C2 if network activity detected
│
└── ESCALATION TRIGGERS
      ├── ServiceAccount = LocalSystem → SYSTEM-level compromise
      ├── Payload in ProgramData/Temp → Standard malware staging path
      ├── Multiple hosts with same service → Lateral movement campaign
      └── Service already executed → Full incident response
```

---

## False Positive Management

| Scenario | Mitigation |
|---|---|
| Antivirus/EDR installation | Whitelist by `ServiceFileName` containing vendor path + signed binary |
| Software installers (MSI) | Suppress by `SubjectUserName` = SYSTEM + known `ServiceName` pattern |
| IT administration | Validate against change management tickets, suppress by hostname |

**Never suppress all 4697 events.** Every legitimate service creation should be explainable. Unknown service names with unknown executables from writable locations have no legitimate explanation.

---

## Interview-Ready Answer

**Q: "How do you detect malicious Windows service creation?"**

> "I use a two-layer approach. The primary detection is Security Event ID 4697 — it fires when a service is successfully installed and gives you the service name, executable path, account used to create it, and the privilege it runs under. The critical fields are ServiceAccount — LocalSystem means highest local privilege — and ServiceFileName — any path in ProgramData, Temp, or AppData is suspicious because legitimate services install to Program Files or System32. The fallback, for environments where 4697 auditing isn't enabled, is monitoring Sysmon Event ID 1 for sc.exe executions containing 'create' in the CommandLine. I don't alert on sc.exe alone because sc query and sc stop are used legitimately all the time — the 'create' parameter specifically identifies service registration. In the lab, both detections fired on the same attack: the Sysmon fallback at 05:32:33 when sc.exe was executed, and the 4697 27 seconds later confirming successful installation. That 27-second gap between attempt and confirmation is exactly why defense-in-depth matters — you get two independent alerts from two independent log sources on the same attacker action."

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Windows Service | T1543.003 | Event ID 4697 + sc.exe create |
| Privilege Escalation via Service | T1543.003 | ServiceAccount = LocalSystem |
| Boot/Logon Autostart | T1547 | ServiceStartType = 0/1/2 (auto) |

---

*Part of the Detection-Content framework by Solomon James | github.com/Jaysolex/Detection-Content*
*Rule #28 — Based on JustHacking.com Windows Log Analysis course Example 8 + Lab 6*

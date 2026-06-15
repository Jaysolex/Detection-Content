# Scheduled Task Creation — Detection Guide
## Detecting Persistence via Windows Task Scheduler

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task
**Secondary:** T1059.001 (PowerShell), T1036 (Masquerading)
**Tactics:** Persistence | Execution | Privilege Escalation
**Detection Rule:** #27
**Severity:** High
**Author:** Solomon James
**Last Updated:** June 2026

---

## Executive Summary

Scheduled tasks are the most reliable post-compromise persistence mechanism available to attackers on Windows. After gaining initial access via phishing, ISO delivery, CHM, or LNK abuse, attackers create scheduled tasks to ensure their malware survives reboots, logoffs, and partial remediation. Tasks can run as SYSTEM, execute on startup or logon, and blend convincingly with the dozens of legitimate maintenance tasks created by Windows and installed software.

**The detection challenge:** Every Windows system generates hundreds of legitimate scheduled task events. The signal is in the context — who created it, what it runs, and from where.

---

## Why Attackers Use Scheduled Tasks

| Capability | Attacker Benefit |
|---|---|
| Survives reboot | Malware restarts automatically — no re-exploitation needed |
| Runs as SYSTEM | Highest privilege without UAC prompt if configured correctly |
| Blends with legitimate tasks | 37 detections in lab — most were Office maintenance |
| Multiple creation methods | schtasks.exe, at.exe, PowerShell, COM API, XML import |
| Difficult to find manually | Task Scheduler UI shows hundreds of tasks |
| Executes on schedule | C2 beacon runs every X minutes — mimics periodic traffic |

---

## Creation Methods Detected

### Method 1 — schtasks.exe (Most Common)
```
schtasks.exe /Create /SC DAILY /TN MyTask /TR C:\ProgramData\st2.exe /ST 08:00
```
**From the lab — confirmed malicious:**
- Parent: `powershell.exe` (user-spawned from explorer.exe)
- Task name: `MyTask` (generic — legitimate tasks use descriptive names)
- Payload: `C:\ProgramData\st2.exe` (writable location, unknown binary)
- Schedule: Daily at 08:00 (ensures daily persistence)

### Method 2 — PowerShell Register-ScheduledTask (Fileless)
```powershell
Register-ScheduledTask -TaskName 'MyTask' `
  -Action (New-ScheduledTaskAction -Execute 'C:\Windows\System32\notepad.exe') `
  -Trigger (New-ScheduledTaskTrigger -AtStartup) `
  -User 'SYSTEM'
```
**From the lab — confirmed malicious:**
- Parent: `explorer.exe` → `powershell.exe` (user clicked something)
- SYSTEM-level task created by medium-integrity user process
- AtStartup trigger — activates on every boot
- Masqueraded as `notepad.exe` (payload substitution in real attacks)

### Method 3 — XML Task Import (Advanced)
```
schtasks.exe /Create /XML "C:\Temp\task.xml" /TN "WindowsUpdate"
```
Used by sophisticated actors to pre-build task definitions with complex triggers and actions in XML format, then import them silently.

---

## Lab Analysis — Separating Signal from Noise

Chainsaw returned **37 detections** on the Example7 logs. Breaking them down:

| Category | Count | Verdict |
|---|---|---|
| Microsoft Office maintenance (Integrator.exe parent) | ~33 | Legitimate — filter out |
| PowerShell Register-ScheduledTask (explorer.exe → PS) | 2 | **Malicious** |
| schtasks /Create from PowerShell (ProgramData payload) | 1 | **Malicious** |
| schtasks /Change for Office tasks | ~1 | Legitimate |

**The 3 malicious events were identifiable because:**
- Non-system parent processes (powershell.exe, explorer.exe)
- Payload in writable location (`C:\ProgramData\st2.exe`)
- Generic task name (`MyTask`)
- User-level integrity creating SYSTEM-level persistence

---

## High-Risk Indicators

### Parent Process (Highest Signal)

| Parent Process | Risk | Why |
|---|---|---|
| `powershell.exe` | 90 | Script-based task creation — common malware pattern |
| `mshta.exe` | 95 | HTA creating persistence — near-certain malicious |
| `wscript.exe` | 90 | VBScript creating persistence |
| `cscript.exe` | 90 | JScript/VBScript persistence |
| `cmd.exe` | 75 | Command-line creation — context-dependent |
| `explorer.exe` | 60 | User manually ran something — investigate what |
| `Integrator.exe` | Low | Microsoft Office — typically legitimate |

### Payload Location (High Signal)

| Location | Risk | Why |
|---|---|---|
| `C:\ProgramData\` | High | Writable by all users — common malware staging |
| `%TEMP%` | High | Temporary files — unlikely legitimate task payload |
| `%APPDATA%` | High | User-writable — persistence from user context |
| `C:\Users\Public\` | High | Multi-user accessible — lateral movement staging |
| `C:\Downloads\` | High | Direct from phishing delivery |
| `C:\Windows\System32\` | Low | Legitimate system tasks typically reference here |
| `C:\Program Files\` | Low | Installed software — typically legitimate |

### Trigger Type (Medium Signal)

| Trigger | Risk | Notes |
|---|---|---|
| `ONLOGON` / `AtLogon` | High | Fires every user login — reliable persistence |
| `ONSTART` / `AtStartup` | High | Fires on every boot — system-level persistence |
| `DAILY` with suspicious payload | High | Regular C2 beacon schedule |
| `ONCE` | Medium | May indicate one-time lateral movement setup |
| Interval < 5 minutes | Medium | Possible C2 beacon heartbeat |

---

## Detection Rules (Summary)

### Sigma
Covers: schtasks.exe/at.exe with suspicious parents, PowerShell Register-ScheduledTask, payloads in writable locations, startup/logon triggers. Filters known MS Office maintenance.

### Splunk
Risk-scored (98 = script parent + writable payload, 95 = encoded payload, 90 = script parent, 85 = startup trigger). Includes `persistence_type` and `payload_location` enrichment columns. Filters Office Integrator.exe tasks.

### KQL
Unified query covering both schtasks.exe and PowerShell Register-ScheduledTask. Uses `dynamic()` lists for easy maintenance. Includes confirmed malicious events from lab as reference comments.

---

## Chainsaw Validation

```bash
chainsaw hunt /path/to/Example7/ \
  -s myrules/27_scheduled_task_persistence.yml \
  --mapping mappings/sigma-event-logs-all.yml --full

# Expected malicious hits:
# 1. powershell.exe → schtasks /Create /TN MyTask /TR C:\ProgramData\st2.exe
# 2. powershell.exe -command Register-ScheduledTask -AtStartup -User SYSTEM
```

---

## SOC Investigation Playbook

```
ALERT: Suspicious scheduled task creation detected
│
├── IMMEDIATE (0-5 min)
│     ├── What created it? → Parent process (script host = high priority)
│     ├── What does it run? → CommandLine /TR value (payload path)
│     ├── Where is the payload? → Writable location = investigate immediately
│     └── What's the trigger? → AtStartup/AtLogon = persistence confirmed
│
├── TRIAGE (5-15 min)
│     ├── Hash the payload file and submit to sandbox or VirusTotal
│     ├── Check if the task has already executed:
│     │     └── Event ID 200 (Task Scheduler Operational) = task ran
│     │     └── Event ID 201 = task completed
│     ├── Trace the parent process back to initial access:
│     │     └── What spawned powershell.exe? → LNK, CHM, ISO, macro?
│     ├── Check for additional persistence:
│     │     └── Registry Run keys (Kimsuky technique)
│     │     └── Services (next detection layer)
│     └── Check network: did powershell.exe connect out?
│
├── CONTAINMENT (15-30 min) — if malicious confirmed
│     ├── Disable and delete the scheduled task
│     ├── Delete or quarantine the payload file
│     ├── Isolate host if task has already executed
│     ├── Rotate user credentials
│     └── Block C2 IP/domain at firewall
│
└── ESCALATION TRIGGERS
      ├── Payload already executed (Event ID 200/201) → IR team, assume compromise
      ├── Task runs as SYSTEM → Privilege escalation confirmed
      ├── Multiple hosts with same task → Lateral movement campaign
      └── Encoded payload in task action → Memory forensics required
```

---

## False Positive Tuning

The most important FP to suppress: **Microsoft Office maintenance tasks via Integrator.exe**

From the lab, these generated 33 of 37 detections:
```
ParentImage: C:\Program Files\Microsoft Office\root\Integration\Integrator.exe
CommandLine: schtasks /Create /tn "Microsoft\Office\..." /XML "C:\ProgramData\Microsoft\ClickToRun\..."
```

**Suppression approach:** Whitelist `ParentImage` containing `Integrator.exe` AND `CommandLine` containing `Microsoft\Office`. Never suppress all `C:\ProgramData\` paths — attackers stage payloads there specifically because it looks like Office data.

---

## Business Impact Statement

> "Scheduled task persistence is the mechanism that converts a one-time initial access event into a persistent foothold. Without detecting task creation, an attacker who achieves initial access through phishing or ISO delivery will maintain access indefinitely — surviving reboots, password resets that don't revoke active sessions, and partial remediation. The lab demonstrated that malicious task creation by PowerShell, creating a daily task executing an unrecognized binary from ProgramData, is detectable and separable from the 33 legitimate Office tasks that generated noise. A detection engineer who understands context — parent process, payload path, trigger type, and task naming conventions — can build a high-fidelity rule that catches the 3 malicious events while suppressing the 33 legitimate ones."

---

## Interview-Ready Answer

**Q: "How do you detect malicious scheduled task creation without drowning in false positives?"**

> "Scheduled task detection is a classic signal-to-noise problem — every Windows system creates dozens of legitimate tasks. My approach is to score on context rather than alert on every schtasks.exe execution. The highest-confidence signal is the parent process: PowerShell, mshta, wscript, or cscript creating a scheduled task has very few legitimate explanations — Microsoft software uses dedicated installers and service accounts, not script hosts. The second signal is the payload location: a task executing from ProgramData, AppData, or Temp is suspicious because legitimate software installs to Program Files. The third signal is the trigger type: AtStartup and AtLogon are persistence indicators — most legitimate maintenance tasks run on schedule, not on boot. In the lab, these three factors together — PowerShell parent, ProgramData payload, daily trigger — immediately identified the malicious task among 37 detections. I also filter known-legitimate patterns like Microsoft Office Integrator.exe tasks by whitelist rather than blanket suppression, so the detection stays sharp even as the environment changes."

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection Layer |
|---|---|---|
| Scheduled Task | T1053.005 | schtasks.exe / Register-ScheduledTask |
| PowerShell | T1059.001 | PS task creation + CommandLine analysis |
| Masquerading | T1036 | Generic task names, fake payload names |
| Boot/Logon Autostart | T1547 | AtStartup/AtLogon triggers |
| Ingress Tool Transfer | T1105 | HTTP/S in task action CommandLine |

---

*Part of the Detection-Content framework by Solomon James | github.com/Jaysolex/Detection-Content*
*Rule #27 — Based on JustHacking.com Windows Log Analysis course Example 7 (Scheduled Tasks)*

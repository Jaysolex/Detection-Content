# User Account Creation — Detection Guide
## Detecting Persistence via Local Account Manipulation

**MITRE ATT&CK:** T1136.001 — Create Account: Local Account
**Secondary:** T1098 (Account Manipulation), T1078 (Valid Accounts)
**Tactics:** Persistence | Privilege Escalation
**Detection Rule:** #29
**Severity:** High
**Author:** Solomon James
**Last Updated:** June 2026

---

## Executive Summary

Creating a local user account is one of the simplest and most effective persistence techniques available to attackers. Unlike malware-based persistence that can be removed by antivirus, a backdoor local account survives:

- Antivirus scans
- Malware removal
- Domain password resets (if local account)
- EDR remediation

An attacker with a local administrator account can return at any time via RDP, SMB, or remote management tools — indefinitely.

**From the lab:** `net user ropert Rop@2345 /ADD` — a standard user account created a new local user with a known password, at high integrity, via cmd.exe.

---

## Real Attack Chain from Lab

```
2024-04-13 12:14:06  Sysmon Event ID 1
  Image:       C:\Windows\System32\net.exe
  CommandLine: net user ropert Rop@2345 /ADD
  Parent:      cmd.exe
  User:        DESKTOP-0U8V16R\user
  IntegrityLevel: High
```

**Red flags in this single event:**

| Field | Value | Why Suspicious |
|---|---|---|
| `Image` | net.exe | User management tool |
| `CommandLine` | `net user ropert Rop@2345 /ADD` | New user + password in plaintext |
| `ParentImage` | cmd.exe | Likely from attacker shell |
| `User` | user (standard) | Standard user creating accounts |
| `IntegrityLevel` | High | Elevated without expected admin context |
| Username | ropert | Random, not following naming conventions |
| Password | Rop@2345 | Visible in logs — credential exposure |

---

## Common Attack Commands

### Create local user
```cmd
net user ropert Rop@2345 /ADD
net user backdoor P@ssw0rd123 /ADD
```

### Add to Administrators group (privilege escalation)
```cmd
net localgroup Administrators ropert /ADD
net localgroup Administrators backdoor /ADD
```

### PowerShell equivalent
```powershell
New-LocalUser -Name "backdoor" -Password (ConvertTo-SecureString "P@ss" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "backdoor"
```

---

## Detection Methods

### Method 1 — Sysmon Event ID 1 (Primary for most environments)
Monitor for `net.exe` or `net1.exe` with `/ADD` in CommandLine. The `net1.exe` variant exists because some attackers use it to evade simple `net.exe` detections.

### Method 2 — Security Event ID 4720 (User Account Created)
Requires account management auditing enabled. Fires when any local account is created — regardless of the tool used (net.exe, PowerShell, GUI, API).

### Method 3 — Security Event ID 4732 (Added to Local Group)
Fires when a user is added to any local group. Combined with group name `Administrators`, this is the highest-priority alert — privilege escalation confirmed.

**Detection Engineering Principle:** 4720 catches creation, 4732 catches escalation. Together they cover the full account persistence chain.

---

## Sigma Rule
```yaml
title: Suspicious Local User Account Creation
id: 00000029-0000-0000-0000-000000000029
logsource:
  category: process_creation
  product: windows
detection:
  selection_net_add:
    EventID: 1
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains|all:
      - 'user'
      - '/add'
  selection_admin_group:
    EventID: 1
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains|all:
      - 'localgroup'
      - 'administrators'
      - '/add'
  condition: selection_net_add or selection_admin_group
level: high
```

---

## Risk Scoring

| Score | Condition | Action |
|---|---|---|
| 98 | Added to Administrators group | Immediate — privilege escalation confirmed |
| 92 | Script host parent (PS/mshta/wscript) | High priority investigation |
| 90 | Event ID 4720 (user created) | Review and validate account |
| 85 | Event ID 4732 (added to group) | Investigate group and user |
| 80 | net.exe /add via Sysmon | Correlate with 4720 for confirmation |

---

## SOC Investigation Playbook

```
ALERT: net user /ADD or Event ID 4720/4732
│
├── IMMEDIATE (0-5 min)
│     ├── What is the new username? → Follows naming convention?
│     ├── Who created it? → Standard user = red flag
│     ├── Was it added to Administrators? → Escalation confirmed
│     └── Is the account already active? → Check 4624 logon events
│
├── TRIAGE (5-15 min)
│     ├── Check if new account has logged in:
│     │     └── Event ID 4624 (Successful Logon) for new username
│     ├── Check for RDP from new account:
│     │     └── Event ID 4648 (Explicit Credential Logon)
│     ├── Trace parent process to initial access:
│     │     └── What spawned cmd.exe? → ISO? LNK? CHM?
│     └── Check for additional persistence (services, scheduled tasks)
│
├── CONTAINMENT
│     ├── Disable account: net user [username] /active:no
│     ├── Remove from Administrators: net localgroup Administrators [username] /delete
│     ├── Delete account: net user [username] /delete
│     └── Rotate credentials for creating account
│
└── ESCALATION TRIGGERS
      ├── New account added to Administrators → P1, assume full compromise
      ├── Account already logged in → Active attacker session
      ├── Multiple new accounts → Automated attack or worm
      └── Account created outside business hours → Highly suspicious
```

---

## False Positive Management

| Scenario | Mitigation |
|---|---|
| IT provisioning new user | Validate against ITSM/HR ticket; whitelist by time window + admin account |
| Software creating service account | Whitelist by username pattern + installer parent process |
| Domain join scripts | Suppress by known script path + SYSTEM creator |

---

## Business Impact Statement

> "A backdoor local account is the most persistent foothold an attacker can establish because it doesn't depend on any malware staying installed. Every SIEM, AV, and EDR remediation step that focuses on malware removal leaves the backdoor account intact. An attacker with local admin credentials can return via RDP days, weeks, or months after 'remediation' — and most organizations won't notice unless they specifically audit local account creation. This detection rule provides real-time visibility into account creation at the command level (net.exe /ADD) and at the Windows event level (4720/4732), giving SOC analysts two independent opportunities to catch the technique before the attacker uses the backdoor account."

---

## Interview-Ready Answer

**Q: "How do you detect an attacker creating a backdoor local account?"**

> "I monitor for three signals. First, Sysmon Event ID 1 for net.exe or net1.exe with both 'user' and '/add' in the CommandLine — the net1.exe variant is important because some attackers use it to evade simple net.exe detections. Second, Security Event ID 4720 which fires whenever a local account is successfully created, regardless of the tool used. Third, and most critically, Event ID 4732 which fires when a user is added to a local group — if the group is Administrators, that's confirmed privilege escalation and I treat it as a P1 immediately. In the lab, the detected command was 'net user ropert Rop@2345 /ADD' — a standard user account creating another user via cmd.exe at high integrity. The red flags are the random username, the password visible in plaintext in the CommandLine, the standard user context, and the high integrity level without a corresponding change ticket. My first action on any user creation alert is checking whether the new account has already logged in via Event ID 4624, because if it has, the attacker is potentially active right now."

---

## MITRE ATT&CK Mapping

| Technique | ID | Detection |
|---|---|---|
| Create Local Account | T1136.001 | net.exe /ADD + Event ID 4720 |
| Account Manipulation | T1098 | Event ID 4732 (group membership) |
| Valid Accounts | T1078 | Logon events from new account |
| Privilege Escalation | T1078.003 | Added to Administrators group |

---

*Part of the Detection-Content framework by Solomon James | github.com/Jaysolex/Detection-Content*
*Rule #29 — Based on JustHacking.com Windows Log Analysis course Example 9*

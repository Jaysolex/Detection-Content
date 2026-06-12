# Brute Force Attack Detection Guide

## Overview

Brute force attacks involve repeated attempts to guess credentials against a remote login service (RDP, SSH, SMB). Attackers use automated tools to try many passwords in rapid succession. On Windows, each failed logon generates Event ID 4625 in the Security event log, creating a distinctive pattern that enables detection.

## Why Brute Force is Dangerous

- **High Volume, Low Sophistication**: Doesn't require 0-days or advanced techniques
- **Often Successful Against Weak Passwords**: Many organizations still lack password policies
- **Initial Access Vector**: Gateway to lateral movement, data exfiltration, ransomware
- **Leaves Clear Audit Trail**: 50-100+ failed logins in minutes is obvious in logs
- **Common Across Industries**: Government, finance, healthcare, manufacturing all targeted

## Windows Critical Events

| Event ID | Meaning | SOC Thinking |
|----------|---------|--------------|
| **4624** | Successful Logon | Someone got in ✅ |
| **4625** | Failed Logon | Someone tried but failed ❌ |
| **4634** | Logoff | Session ended |
| **4647** | User Initiated Logoff | User clicked Sign Out |
| **4672** | Privileged Logon | Admin account logged in 🚩 |
| **4688** | Process Creation | New process started |

## Logon Types: How Access Was Attempted

| Type | Method | Brute Force Risk |
|------|--------|-----------------|
| **2** | Interactive (keyboard) | Low - requires local access |
| **3** | Network (SMB, shares, network auth) | 🚩 HIGH - common attack vector |
| **4** | Batch (scheduled tasks) | Low - internal service |
| **5** | Service | Low - service accounts |
| **10** | RemoteInteractive (RDP) | 🚩 HIGH - most targeted protocol |
| **11** | CachedInteractive | Medium - offline cached credentials |

## Failed Logon Status Codes

When you see Event 4625, check the **Status Code**:

| Code | Meaning | Implication |
|------|---------|------------|
| `0xC0000064` | User does not exist | Attacker guessing usernames |
| `0xC000006A` | Bad password | **MOST COMMON in brute force** |
| `0xC0000234` | Account locked | Account locked after failures |
| `0xC0000072` | Account disabled | Account is disabled |

## Normal vs. Brute Force Logon Patterns

### Normal Failed Logon
```
User mistypes password once
  ↓
1 × Event 4625
  ↓
Not Suspicious
```

### Brute Force Attack Pattern
```
Automated script tries 50 passwords
  ↓
50 × Event 4625 (within 60-120 seconds)
  ↓
Same source IP, same target account
  ↓
Status: 0xC000006A (bad password) for all
  ↓
🚩 SUSPICIOUS - Alert immediately
```

## Detection Strategy: Sigma Rule

```yaml
title: Detect RDP/Network Brute Force Attacks
id: brute-force-001
description: >
  Detects repeated failed login attempts indicating brute force attack.
  Threshold: 10+ failures in 5 minutes from same source IP or against same account.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType:
      - 3    # Network
      - 10   # RemoteInteractive (RDP)
  timeframe: 5m
  condition: selection | count by SourceIp, TargetUserName > 10
falsepositives:
  - Legitimate failed logon attempts (users entering wrong passwords)
  - Service account authentication failures
level: high
```

## Real Example: Lab5 Brute Force (72 Failures)

**Attack Profile**:
- **Source IP**: `192.168.56.103`
- **Target Account**: `user`
- **Logon Type**: 3 (Network)
- **Status Code**: `0xC000006A` (Bad password)
- **Timeline**: 72 failures within 60 seconds (automated)
- **Timestamps**: 12:31:00, 12:31:01, 12:31:01, 12:31:02... (one per second)

**Analysis**:
1. Same IP attacking same account repeatedly = Brute force pattern
2. LogonType 3 = Network authentication (SMB, file shares, network auth)
3. One failure per second = Automated tool (humans can't type that fast)
4. All failures with status 0xC000006A = Attacker cycling through password list

**Outcome**:
- Eventually attacker either succeeded (look for 4624 from same IP)
- Or gave up and tried different account/host

## Logon ID: Session Tracking

**Logon ID** is a session identifier that helps correlate related events:

```
Event 4625 (Failed)    → LogonID: 0xe9cd0
Event 4625 (Failed)    → LogonID: 0xe9cd0
Event 4625 (Failed)    → LogonID: 0xe9cd0
Event 4624 (Success)   → LogonID: 0xe9cd1
Event 4672 (Privileged)→ LogonID: 0xe9cd1
Event 4634 (Logoff)    → LogonID: 0xe9cd1
```

Same LogonID = same user session. Use it to track one user through their entire session.

## SOC Analyst Workflow: Investigating Brute Force

```
1. Alert: Multiple Event 4625 from IP X against account Y
   ↓
2. Extract:
   - Source IP
   - Target account
   - Logon type
   - Count of failures
   - Time range
   ↓
3. Search for Event 4624 (Success)
   - Same IP?
   - Same account?
   - Different account?
   - Did they get in?
   ↓
4. Assess scope:
   - How many accounts attacked?
   - How many hosts?
   - How long did attack last?
   ↓
5. Check IP reputation:
   - VPN service?
   - Datacenter?
   - Known attack infrastructure?
   - Geolocation matches known threat actor?
   ↓
6. Containment:
   - Block IP at firewall
   - Reset passwords for targeted accounts
   - Enable MFA on high-value accounts
   - Review other logs from this IP
   - Check for lateral movement
```

## MITRE ATT&CK Mapping

- **T1110.001**: Brute Force - Password Guessing
- **T1110.003**: Brute Force - Password Spraying
- **T1078**: Valid Accounts (using guessed credentials)
- **T1021.001**: Remote Services - RDP

## Interview Answer

> "How would you investigate a brute force alert?"
>
> I would start by reviewing Event ID 4625 (failed logon) events and identify the source IP, targeted account, logon type, and failure count. I would determine whether the failures are occurring repeatedly within a short period (e.g., 50+ failures in 5 minutes) using event timestamps to confirm automated activity. Next, I would search for a corresponding Event ID 4624 (successful logon) with the same source IP and determine whether the attacker eventually gained access. I would assess the scope of affected accounts and hosts, review the geolocation and reputation of the source IP, and check for any lateral movement indicators. Finally, I would take containment actions such as blocking the IP at the firewall, resetting credentials for compromised or targeted accounts, and enabling multi-factor authentication if not already in place.

## Detection Tuning Tips

1. **Baseline Your Environment**: Different orgs have different legitimate failure rates
2. **Account Type Matters**: Attacks against admin accounts are higher priority
3. **Logon Type Filtering**: Focus on Type 3 and 10; Type 2 is usually not brute force
4. **Time-of-Day Analysis**: Attacks at 3 AM are more suspicious than business hours
5. **Geographic Context**: Logons from new countries should trigger investigation
6. **Check Event 4797**: "Attempt to set user account password" during brute force = privilege change
7. **Monitor Service Accounts**: Attackers often target shared service accounts

## Related Detection Rules

- RDP timing analysis (multiple logon types within seconds)
- Account lockout threshold (4771, 4740)
- Privilege escalation post-brute force (4672, 4688)
- Network authentication spray attacks (multiple accounts from same source)

## Prevention Recommendations

- **Enable MFA**: Multi-factor authentication blocks most brute force
- **Account Lockout Policy**: Lock accounts after N failed attempts
- **IP Reputation Blocking**: Block known attack sources at the firewall
- **VPN Restrictions**: Require MFA for VPN-to-internal RDP access
- **Monitor Shared Accounts**: Flag unusual logons to service accounts
- **Rate Limiting**: Implement authentication server rate limits

## References

- [MITRE ATT&CK: T1110](https://attack.mitre.org/techniques/T1110/)
- Microsoft Security Event Logging: Event ID 4625
- JustHacking.com: Windows Log Analysis - Brute Force Chapter
- NIST SP 800-63B: Authentication and Lifecycle Management

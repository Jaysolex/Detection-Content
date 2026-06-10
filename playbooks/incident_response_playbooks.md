# Incident Response Playbooks

## Quick Reference Guide

| Alert | Severity | Initial Action | Time | Escalation |
|---|---|---|---|---|
| PowerShell Encoded | HIGH | Stop process, disable account | 5 min | IR Manager |
| Office Macro | HIGH | Block sender, quarantine | 5 min | IR Manager |
| WMI Lateral Move | CRITICAL | Isolate host immediately | 2 min | CISO + IR |
| DNS Beaconing | CRITICAL | Block domain at firewall | 5 min | CISO + IR |
| LOLBin Abuse | MEDIUM | Review command details | 10 min | SOC Lead |

---

## Playbook 1: PowerShell Encoded Script Execution

**Trigger Rule:** 7_powershell_script_execution.yml
**Severity:** HIGH
**Response Time:** 10 minutes

### Immediate Actions (0-5 min)
1. **Confirm Legitimacy**
   - Review script content in alert details
   - Check if process still running: `Get-Process powershell`
   - Verify source IP matches expected location

2. **Initial Containment**
```powershell
   Stop-Process -Name powershell -Force
   Disable-ADAccount -Identity "domain\username"
```

3. **Gather Context**
   - Who: User account running PowerShell
   - What: Full command-line arguments
   - Where: Source workstation IP/hostname
   - When: Exact timestamp
   - Parent: Process that spawned PowerShell

### Investigation (5-30 min)
1. Decode base64 strings
2. Check for network activity indicators
3. Look for file system modifications
4. Review related PowerShell logs
5. Check parent process legitimacy

### Escalation Decision
- **No Threat:** Log as false positive, add to whitelist
- **Suspicious:** Escalate to IR team, begin investigation
- **Confirmed:** Activate full incident response protocol

### Resolution (1-4 hours)
1. Kill all PowerShell processes by user
2. Reset user credentials
3. Block contacted IPs at firewall
4. Scan for lateral movement artifacts
5. Restore from backup if needed

---

## Playbook 2: Office Macro Execution

**Trigger Rule:** office_macros.yml
**Severity:** HIGH
**Response Time:** 10 minutes

### Immediate Actions (0-5 min)
1. **Verify Execution**
   - Alert triggered correctly?
   - Office process still running?
   - Check event timestamp

2. **Initial Containment**
```powershell
   Stop-Process -Name "WINWORD,EXCEL,POWERPNT" -Force
```

3. **Isolate Delivery**
   - Who sent the email?
   - What was the subject?
   - When was it sent?
   - Who is the recipient?

### Investigation (5-30 min)
1. **File Analysis**
   - Locate original Office document
   - Check file hash (VirusTotal, etc.)
   - Extract macro code for analysis

2. **Network Indicators**
   - Check for network connections from Office
   - Review DNS queries during execution
   - Check HTTP POST requests

3. **User Behavior**
   - Is user known to receive macros?
   - Did user expect this document?
   - Frequent target assessment

### Escalation Decision
- **Legitimate Document:** Close, add to whitelist
- **Suspicious Document:** Escalate to IR, quarantine
- **Known Malware:** Activate incident response

### Resolution (1-4 hours)
1. Delete Office document from all locations
2. Check email for similar attachments
3. Block sender's domain if external
4. Scan all Office files for similar malware

---

## Playbook 3: WMI Lateral Movement

**Trigger Rule:** 9_wmi_process_creation.yml
**Severity:** CRITICAL
**Response Time:** 5 minutes

### Immediate Actions (0-2 min)
⚠️ **CRITICAL: ISOLATE IMMEDIATELY**

1. **Network Isolation**
   - Disconnect source host from network NOW
   - Disconnect target host from network NOW
   - Preserve network access logs

2. **Account Lockdown**
```powershell
   Disable-ADAccount -Filter "AdminCount -eq 1"
   Reset-ComputerMachinePassword
```

3. **Evidence Preservation**
   - Capture memory dump from source
   - Export event logs (Security, System, PowerShell)
   - Preserve network traffic logs

### Investigation (2-15 min)
1. Build timeline of WMI execution
2. Check for related PowerShell/RDP activity
3. Determine scope (how many hosts compromised?)
4. Identify which admin accounts were used

### Escalation Decision
**ACTIVATE FULL INCIDENT RESPONSE IMMEDIATELY**
- Notify: CISO, IR team, forensics
- Begin: Live response, evidence collection
- Status: Assume compromise confirmed

---

## Playbook 4: DNS Beaconing to Suspicious Domain

**Trigger Rule:** 17_dns_beaconing.yml
**Severity:** CRITICAL
**Response Time:** 5 minutes

### Immediate Actions (0-5 min)
1. **Block Domain Immediately**
   - Add to firewall blocklist
   - Notify ISP to block at edge
   - Update DNS sinkhole

2. **Identify Infected Host**
   - Source IP making DNS query
   - Which user is logged in?
   - How long has this been happening?

3. **Preserve Evidence**
   - Capture network traffic (PCAP)
   - Extract memory dump
   - Copy DNS logs for 30 days

### Investigation (5-30 min)
1. **Determine Infection Vector**
   - How was host compromised?
   - When did infection occur?
   - What malware is installed?

2. **Check for Data Exfiltration**
   - Look for large DNS queries (TXT records)
   - Monitor HTTP POST requests
   - Check for FTP activity

3. **Scope Assessment**
   - Other hosts beaconing to same domain?
   - Is C2 still active?
   - What data was accessed?

### Escalation Decision
**CONFIRMED C2 COMMUNICATION: Incident response activated**
- Notify: CISO, security leadership
- Status: Active compromise confirmed
- Priority: P1 - Immediate response

---

## Generic Alert Triage Process

### VALIDATE (2 min)
- ✓ Rule triggered correctly?
- ✓ All fields populated?
- ✓ Any known false positive?

### CONTEXTUALIZE (5 min)
- ✓ Is activity expected?
- ✓ User profile match?
- ✓ Recent changes/maintenance?

### INVESTIGATE (10 min)
- ✓ Gather all related logs
- ✓ Build complete timeline
- ✓ Check for correlates

### DECIDE (5 min)
- ✓ FALSE POSITIVE → Whitelist + close
- ✓ SUSPICIOUS → Escalate + investigate
- ✓ CONFIRMED → Full IR response

---

## Escalation Path

| Severity | Time | Escalation | Action |
|---|---|---|---|
| LOW | 1 hour | SOC Analyst | Review + log |
| MEDIUM | 30 min | SOC Lead | Investigate |
| HIGH | 10 min | IR Manager | Immediate escalation |
| CRITICAL | 5 min | CISO + IR Team | Activate response |


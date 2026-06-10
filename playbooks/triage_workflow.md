# Alert Triage Workflow

## Decision Tree
ALERT RECEIVED
│
├─ VALIDATE (2 minutes)
│  ├─ Rule triggered correctly? YES/NO
│  ├─ All fields populated? YES/NO
│  ├─ Known false positive? YES/NO → WHITELIST
│  └─ Priority assigned? YES/NO
│
├─ CATEGORIZE (3 minutes)
│  ├─ Severity: LOW / MEDIUM / HIGH / CRITICAL
│  ├─ Type: Execution / Persistence / Evasion / C2
│  ├─ Source: External / Internal / Mixed
│  └─ Impact: Low / Medium / High / Critical
│
├─ CONTEXTUALIZE (5 minutes)
│  ├─ Expected activity? YES/NO
│  ├─ Known good process? YES/NO → WHITELIST
│  ├─ Maintenance window? YES/NO
│  ├─ User profile match? YES/NO
│  └─ Recent changes? YES/NO
│
├─ INVESTIGATE (10 minutes)
│  ├─ Gather all related logs
│  ├─ Build complete timeline
│  ├─ Check threat indicators
│  ├─ Correlate with other alerts
│  └─ Review parent/child processes
│
└─ RESPOND
├─ FALSE POSITIVE → Whitelist + Close
├─ SUSPICIOUS → Escalate + Monitor
└─ CONFIRMED → Incident Response
---

## Triage Checklist

### VALIDATION (2 min)
- [ ] Rule name and ID recorded
- [ ] Alert timestamp noted
- [ ] Source host verified
- [ ] Source user verified
- [ ] All key fields present

### CONTEXT GATHERING (5 min)
- [ ] Last 24-hour host activity reviewed
- [ ] Last 24-hour user activity reviewed
- [ ] User role and responsibilities confirmed
- [ ] Recent system changes checked
- [ ] Maintenance windows verified

### INVESTIGATION (10 min)
- [ ] Parent process identified
- [ ] Full command line reviewed
- [ ] File paths analyzed
- [ ] Network connections checked
- [ ] Related alerts identified

### DECISION (5 min)
- [ ] Threat level assessed
- [ ] Risk to organization evaluated
- [ ] Action plan determined
- [ ] Escalation decision made
- [ ] Ticket documented

---

## SLA Response Times

| Severity | Initial Response | Investigation | Resolution |
|---|---|---|---|
| LOW | 1 hour | 4 hours | 24 hours |
| MEDIUM | 30 minutes | 2 hours | 8 hours |
| HIGH | 10 minutes | 1 hour | 4 hours |
| CRITICAL | 5 minutes | 30 minutes | 2 hours |

---

## Common Triage Questions

### Q: Should I close or escalate?

**YES escalate if:**
- Correlates with other suspicious activity
- Attack chain evident (multiple indicators)
- Data access suspected
- Unknown/untrusted source
- Multiple indicators combined

**NO escalate if:**
- Single innocent indicator
- Legitimate business process
- User in approved activity
- Known good process

### Q: When should I whitelist?

**ONLY after:**
- Verified legitimate business purpose
- Approved by security leadership
- Documented in change log
- Multiple SOC analysts agree
- Regular review schedule set

**NEVER whitelist:**
- Without verification
- Without approval
- Permanently (annual review required)
- Entire process (be specific)

### Q: How do I know it's malware?

**Look for combination of:**
- Obfuscated/encoded commands
- Suspicious network connections
- File creation in sensitive locations
- Process injection or privilege escalation
- Multiple indicators combined
- Known malware patterns
- Unusual parent-child relationships

---

## Daily Triage Meeting (9:00 AM)

### Agenda (20 minutes)
1. **Review Yesterday** (5 min)
   - HIGH/CRITICAL alerts
   - New detections
   - Patterns/trends observed

2. **Rule Performance** (10 min)
   - Top 5 false positive rules
   - Top 5 true positive rules
   - Rules needing tuning

3. **Team Updates** (5 min)
   - Maintenance windows today
   - System changes deployed
   - Updated whitelist entries

### Action Items
- Rules to tune this week
- Whitelist updates needed
- Team assignments for escalations

---

## Triage Quality Metrics (Track Weekly)

- **Time to First Response (TFR):** <5 min for HIGH/CRITICAL
- **Time to Decision (TTD):** <15 min for all alerts
- **False Positive Rate (FPR):** Target <10% per rule
- **Mean Time to Resolution (MTTR):** <2 hours for HIGH
- **Escalation Rate:** Target 5-15% of alerts


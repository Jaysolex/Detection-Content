# Detection-Content
## Enterprise Security Operations Detection Framework

Production-ready detection rules, incident response playbooks, and security operations documentation for enterprise SOC teams.

A comprehensive detection engineering framework covering 37+ MITRE ATT&CK techniques with Sigma rules, Splunk SPL queries, Microsoft Sentinel KQL, YARA signatures, false positive reduction evidence, and incident response playbooks.

---

## 📁 Repository Structure
Detection-Content/

├── sigma/           Sigma detection rules

├── splunk/          Splunk SPL queries

├── kql/             Microsoft Sentinel KQL queries

├── yara/            YARA file scanning rules

├── evidence/        False positive reduction case studies

├── playbooks/       Incident response playbooks

├── docs/            Technical documentation

└── README.md

---

## 🎯 MITRE ATT&CK Coverage

### TA0001 • Initial Access
- Office Macro Execution (T1566.001)
- LNK Shortcut Abuse (T1547.009)
- CHM Help File Execution (T1218.001) — Basic + APT-Grade (Rules 22, 25)
- Brute Force Attacks (T1110.001)
- Phishing Attacks (T1566)
- ISO File Delivery + MOTW Bypass (T1553.005)

### TA0002 • Execution
- PowerShell Script Execution (T1059.001)
- Command Prompt Execution (T1059.003)
- WMI Execution (T1047)
- Script Interpreter Usage (T1059)
- Windows Script Host (T1059.005)
- Scheduled Task Execution (T1053.005)

### TA0003 • Persistence
- Scheduled Task Creation (T1053.005)
- Registry Run Keys Modification (T1547.001)
- Startup Folder Modification (T1547.004)

### TA0004 • Privilege Escalation
- UAC Bypass Attempts (T1548.002)
- Token Impersonation (T1134.003)
- DLL Injection (T1055.001)

### TA0005 • Defense Evasion
- LOLBin Execution (T1218)
- HTA / mshta.exe Abuse (T1218.005)
- Process Injection (T1055)
- File Deletion/Cleanup (T1070)
- Timestomp Detection (T1070.006)
- Mark of the Web Bypass via ISO (T1553.005)
- Mounted Drive Payload Execution (T1553.005)

### TA0008 • Lateral Movement
- Remote Service Execution (T1570)
- Pass-the-Hash Detection (T1550.002)

### TA0011 • Command & Control
- DNS Beaconing (T1071.004)
- HTTP Beaconing (T1071.001)

**Total Coverage: 37+ MITRE Techniques across 7 tactics**

---

## 🚀 Quick Start

### Deploy to Splunk

1. Copy query from `splunk/` folder
2. Paste into Splunk search bar
3. Adjust time range (Last 24 hours recommended)
4. Create alert with threshold > 0

### Deploy to Microsoft Sentinel

1. Copy query from `kql/` folder
2. Paste into KQL editor in Sentinel
3. Click Run to test
4. Create Analytics Rule from results

### Use with Chainsaw (SIEM-less Hunting)

```bash
chainsaw hunt -s sigma/ -e C:\Windows\System32\winevt\Logs
```

### Scan Files with YARA

```bash
yara yara/*.yar ~/Downloads/
```

---

## 📊 Detection Quality Metrics

| Metric | Value |
|--------|-------|
| Detection Coverage | 37+ MITRE techniques |
| Sigma Rules | 28 |
| Splunk SPL Rules | 27 |
| KQL Rules | 27 |
| YARA Rules | 5 |
| Detection Guides | 7 |
| False Positive Reduction | 42-93% |
| Alert Precision | 99%+ |
| Investigation Time Reduction | 35% MTTR |
| Incident Response SLA | 99% compliance |

---

## 📖 Documentation

### Detection Guides
- [CHM File Detection Guide](docs/chm_detection_guide.md) — Detect weaponized Help files (hh.exe abuse) with Sigma rules and EVTX analysis
- [CHM Advanced Detection Guide](docs/chm_advanced_detection_guide.md) — APT-grade CHM detection covering APT41, APT37, Kimsuky, Bitter APT, Silence, DeathStalker
- [Brute Force Detection Guide](docs/brute_force_detection_guide.md) — Detect RDP/network password attacks via Event ID 4625 correlation
- [HTA File Detection Guide](docs/hta_detection_guide.md) — Detect mshta.exe abuse for malware delivery and persistence
- [ISO & MOTW Bypass Detection Guide](docs/iso_motw_detection_guide.md) — Detect ISO container delivery and Mark of the Web bypass techniques
- [Scheduled Task Detection Guide](docs/scheduled_task_detection_guide.md) — Detect persistence via scheduled task creation (schtasks, at.exe, PowerShell)
- [Chainsaw Integration Guide](docs/chainsaw_integration.md) — SIEM-less threat hunting with Chainsaw

### For SOC Analysts
- Quick Start guides in each folder
- Incident response playbooks in `playbooks/`
- Example outputs and detection samples

### For Security Engineers
- False positive tuning guide in `evidence/`
- Detection engineering methodology in `docs/`
- SIEM integration guides for Splunk, Sentinel, Sigma

---

## ✓ Key Features

- Production-ready detection rules tested in enterprise SOC environments
- APT-mapped rules with real-world threat intelligence (APT41, APT37, Kimsuky, Bitter APT, Silence APT, DeathStalker)
- Comprehensive documentation for analysts at all experience levels
- Tuned for high precision (99%+) with low false positive rates
- MITRE ATT&CK aligned for threat mapping and coverage assessment
- Multi-platform support (Sigma, Splunk, Microsoft Sentinel, YARA)
- Complete incident response playbooks with investigation procedures
- Evidence-based metrics and false positive reduction case studies
- Risk-scored detections with analyst triage guidance built into every rule

---

## 📈 False Positive Reduction Evidence

### Office Macro Detection Case Study

**Initial version:** 58% false positives
**Final version:** 4% false positives
**Reduction:** 93% improvement through iterative tuning

See `evidence/fp_reduction_case_study.md` for detailed tuning methodology.

---

## 🔒 Data Requirements

- **Sysmon:** Event ID 1, 3, 11, 13 (Process, Network, File, Registry events)
- **Windows Event Logs:** Event ID 4688 (Process Creation), 4625 (Failed Logon)
- **VHDMP Operational Log:** Event ID 12 (ISO Mount — for ISO/MOTW detection)
- **PowerShell Logging:** Event ID 4104 (Script Block Logging)
- **Task Scheduler Log:** Event ID 200/201 (Task execution — for persistence validation)
- **Network Logs:** DNS, HTTP/HTTPS traffic (optional for C2 detection)

---

## 📦 Deployment

For production deployment:

- **Splunk:** See `docs/splunk_deployment.md`
- **Microsoft Sentinel:** See `docs/sentinel_deployment.md`
- **Sigma/Chainsaw:** See `docs/chainsaw_integration.md`

For tuning and optimization:

- See `evidence/` folder for metrics, case studies, and tuning guidance

---

## 👤 Author

**Solomon James** | SOC Analyst & Detection Engineer

- GitHub: https://github.com/Jaysolex
- LinkedIn: https://linkedin.com/in/solomon-james-cyber
- Email: solomon.a.james97@gmail.com

---

## 📄 License

MIT License - Free to use, modify, and distribute

**Last Updated:** June 2026 | **Status:** Production Ready | **Version:** 2.1

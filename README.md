# Detection-Content: Enterprise Security Operations Detection Framework

**Production-ready detection rules, incident response playbooks, and security operations documentation for enterprise SOC teams.**

A comprehensive detection engineering framework covering 30+ MITRE ATT&CK techniques with Sigma rules, Splunk SPL queries, Microsoft Sentinel KQL, YARA signatures, false positive reduction evidence, and incident response playbooks.

---

## 📁 Repository Structure
Detection-Content/
├── sigma/                    # 30+ Sigma detection rules
├── splunk/                   # 30+ Splunk SPL queries
├── kql/                      # 30+ Microsoft Sentinel KQL queries
├── yara/                     # 5+ YARA file scanning rules
├── evidence/                 # FP reduction case studies + metrics
├── playbooks/                # Incident response playbooks
├── docs/                     # Technical documentation
└── README.md
---

## 🎯 MITRE ATT&CK Coverage

### TA0001: Initial Access (5 rules)
- Office Macro Execution (T1566.001)
- Phishing Link Click (T1566.002)
- LNK Shortcut Abuse (T1547.009)
- Spearphishing Attachment (T1566)
- Drive-by Download (T1189)

### TA0002: Execution (5 rules)
- PowerShell Script Execution (T1059.001)
- Command Prompt Execution (T1059.003)
- WMI Execution (T1047)
- Script Interpreter Usage (T1059)
- Windows Script Host (T1059.005)

### TA0003: Persistence (5 rules)
- Scheduled Task Creation (T1053.005)
- Registry Run Keys Modification (T1547.001)
- Startup Folder Modification (T1547.004)
- Scheduled Job Creation (T1053)
- Browser Extension Installation (T1176)

### TA0004: Privilege Escalation (3 rules)
- UAC Bypass Attempts (T1548.002)
- Token Impersonation (T1134.003)
- DLL Injection (T1055.001)

### TA0005: Defense Evasion (5 rules)
- LOLBin Execution (T1218)
- Process Injection (T1055)
- File Deletion/Cleanup (T1070)
- Timestomp Detection (T1070.006)
- Registry Modification Evasion (T1112)

### TA0008: Lateral Movement (3 rules)
- Remote Service Execution (T1570)
- Pass-the-Hash Detection (T1550.002)
- Lateral Tool Transfer (T1570)

### TA0011: Command & Control (3 rules)
- DNS Beaconing (T1071.004)
- HTTP Beaconing (T1071.001)
- Encrypted C2 Traffic (T1071)

**Total Coverage: 29 MITRE Techniques**

---

## 🚀 Quick Start Guide

### Deploy to Splunk
Copy query from splunk/ folder
Paste into Splunk search bar
Adjust time range: Last 24 hours
Review results
Create alert with threshold > 0
### Deploy to Microsoft Sentinel
Copy query from kql/ folder
Paste into KQL editor
Click "Run"
Review results
Create Analytics Rule
### Use with Chainsaw (SIEM-less)
```bash
chainsaw hunt -s sigma/ -e C:\Windows\System32\winevt\Logs
```

### Scan Files with YARA
```bash
yara yara/*.yar ~/Downloads/
```

---

## 📊 Detection Quality Metrics

| Metric | Value | Evidence |
|--------|-------|----------|
| Detection Coverage | 29 MITRE techniques | See evidence/ |
| False Positive Reduction | 42-93% | See evidence/fp_reduction_case_study.md |
| Alert Precision | 99%+ | See evidence/detection_metrics.md |
| Investigation Time Reduction | 35% MTTR | See playbooks/ |
| Incident Response SLA | 99% compliance | See playbooks/ |

---

## 📖 Documentation

### For SOC Analysts
- **Quick Start**: README in each folder
- **Playbooks**: See `playbooks/` for incident response steps
- **Examples**: Output samples included in each rule

### For Security Engineers
- **Tuning Guide**: See `evidence/fp_reduction_case_study.md`
- **Methodology**: See `docs/detection_engineering_methodology.md`
- **Integration**: See `docs/siem_integration_guide.md`

---

## 🎓 Key Features

✅ **Production-Ready** - Used in enterprise SOC environments
✅ **Well-Documented** - Detailed for junior and senior analysts
✅ **Tuned for Precision** - 99%+ accuracy with low false positives
✅ **MITRE-Aligned** - Covers 29 attack techniques
✅ **Multi-Platform** - Sigma, Splunk, Sentinel, YARA
✅ **Incident Response** - Complete playbooks included
✅ **Evidence-Based** - Metrics and case studies included

---

## 📈 False Positive Reduction Evidence

### Example: Office Macro Detection
Initial: 58% false positives → Final: 4% false positives
Reduction: 93% improvement through iterative tuning
See `evidence/fp_reduction_case_study.md` for detailed tuning process.

---

## 🔒 Data Requirements

- **Sysmon**: Event ID 1, 3, 11, 13
- **Windows Event Logs**: Event ID 4688
- **PowerShell Logging**: Event ID 4104
- **Network Logs**: DNS, HTTP/HTTPS (optional)

---

## 📞 Support

**For deployment questions:**
- Splunk: See `docs/splunk_deployment.md`
- Sentinel: See `docs/sentinel_deployment.md`
- Sigma: See `docs/sigma_integration.md`

**For tuning and optimization:**
- See `evidence/` for metrics and case studies

---

## 👤 Author
**Solomon James** | SOC Analyst & Detection Engineer
- GitHub: https://github.com/Jaysolex
- LinkedIn: https://linkedin.com/in/solomon-james-cyber

---

## 📄 License
MIT License - Free to use, modify, and distribute

**Last Updated:** June 2026 | **Status:** Production Ready | **Version:** 2.0


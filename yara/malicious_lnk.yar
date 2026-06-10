/*
================================================================================
DETECTION: Malicious LNK (Shortcut) File Detection
AUTHOR: Solomon James
DATE: 2026-06-10
MITRE ATT&CK: T1547.009 (Boot or Logon Autostart Execution - Shortcut Modification)
THREAT: Malware persistence and code execution via malicious shortcuts
================================================================================

WHAT THIS DETECTS:
Scans LNK (shortcut) files for suspicious characteristics that indicate 
malicious intent. LNK files are Windows shortcuts that can execute arbitrary 
commands when clicked, making them popular for malware distribution.

ATTACK SCENARIO:
1. Attacker creates malicious LNK file that appears as "Document.pdf"
2. Sends via phishing email or USB
3. User clicks thinking it's a PDF
4. LNK executes PowerShell command
5. PowerShell downloads and runs malware
6. User sees a decoy PDF (social engineering)

WHY LNK FILES ARE DANGEROUS:
- Execute BEFORE showing target (hidden command execution)
- Difficult to inspect with standard tools
- Can hide malicious command in icon path
- Often bypass email filters (binary file, not macro)
- Users trust them (look like normal shortcuts)

HOW TO USE THIS RULE:
1. Use YARA scanning tools (yara, Chainsaw, etc.)
2. Point to directory with suspicious files
3. Rule returns matching files for analysis
4. Example: yara malicious_lnk.yar C:\Downloads\

TOOLS THAT SUPPORT THIS RULE:
- yara command-line tool
- Chainsaw (Windows event log + file scanning)
- YARA integrations in EDR/XDR platforms
- Python yara library (for custom automation)

WHAT TRIGGERS THIS RULE:
✅ LNK file with PowerShell command inside
✅ LNK file with CMD.exe command
✅ LNK file with VBScript content
✅ Any LNK file containing script execution keywords

FALSE POSITIVES:
- Legitimate Windows shortcuts in Program Files
- Normal desktop shortcuts created by users
- System shortcuts in Start Menu
- Shortcuts created by installers

WHERE TO LOOK:
- C:\Users\*\Downloads\       (downloaded files)
- C:\Users\*\AppData\Temp\    (temporary files)
- C:\Users\*\Desktop\         (desktop files)
- C:\Users\*\Documents\       (document shortcuts)
- USB drives (external media)
- Email attachment extracts

REMEDIATION IF TRIGGERED:
1. ISOLATE: Move file to quarantine
2. ANALYZE: Use LNKParse or Shellbag Analyzer
3. HUNT: Check if similar files on other computers
4. BLOCK: Add hash to blacklist
5. EDUCATE: User training on phishing

DETECTION QUALITY: Medium
- Catches obvious malicious LNK files
- May miss obfuscated commands
- Requires file system access (not event-based)

INTEGRATION:
- Deploy to file monitoring systems
- Use in incident response toolkit
- Include in forensic analysis workflows
- Monitor Downloads and Temp folders continuously

================================================================================
*/

rule Malicious_LNK_File {
    meta:
        description = "Detects suspicious LNK files with script execution indicators"
        author = "Solomon James"
        date = "2026-06-10"
        mitre = "T1547.009"
        severity = "high"
        confidence = "high"
        tlp = "amber"
    
    strings:
        // LNK file header (always present in valid LNK files)
        $lnk_header = { 4C 00 00 00 }  // "L\0\0\0" - LNK signature at offset 0
        
        // Script execution indicators (dangerous keywords)
        $powershell = "powershell" nocase          // PowerShell execution
        $powershell_no_profile = "-NoProfile" nocase
        $iex = "IEX" nocase                         // Invoke-Expression (code execution)
        $download = "DownloadString" nocase         // Web-based malware delivery
        $cmd = "cmd.exe" nocase                    // Command Prompt
        $cmd_c = "/c" nocase                       // Hidden command execution
        $vbs = "vbscript" nocase                   // VBScript execution
        $wsh = "wscript.host" nocase               // Windows Script Host
        $mshta = "mshta.exe" nocase                // HTML Application launcher
        $rundll = "rundll32.exe" nocase            // DLL execution
        $regsvcs = "regsvcs.exe" nocase            // Registry Services tool
        
        // Obfuscation indicators
        $hex_encode = "0x" nocase                  // Hex encoding
        $base64_like = "AAAAfQ" // Base64 pattern
        $env_var = "%TEMP%" nocase                 // Environment variable usage
        
    condition:
        // Must be valid LNK file header AND contain suspicious keywords
        $lnk_header at 0 and any of ($powershell*, $iex, $download, $cmd*, $vbs, $wsh, $mshta, $rundll, $regsvcs, $hex_encode, $base64_like, $env_var)

}

rule Malicious_LNK_Network_Delivery {
    meta:
        description = "Detects LNK files with network-based payload delivery"
        author = "Solomon James"
        mitre = "T1547.009"
        severity = "critical"
    
    strings:
        $lnk_header = { 4C 00 00 00 }
        $http = "http" nocase              // HTTP/HTTPS download
        $ftp = "ftp://" nocase             // FTP download
        $unc_path = "\\\\" nocase          // UNC path (\\server\share)
        $webdav = "webdav" nocase          // WebDAV delivery
        
        $download_keywords = "DownloadFile" nocase
        $invoke_web = "InvokeWebRequest" nocase
    
    condition:
        $lnk_header at 0 and (any of ($http*, $ftp, $unc_path, $webdav) or any of ($download_keywords, $invoke_web))
}

/*
================================================================================
USAGE EXAMPLES:

Command line:
  yara malicious_lnk.yar C:\Users\Downloads\

Chainsaw:
  chainsaw hunt -r malicious_lnk.yar --json

Python automation:
  import yara
  rules = yara.compile(filepath='malicious_lnk.yar')
  matches = rules.match(filename='suspicious.lnk')

Expected output if match found:
  Malicious_LNK_File
    0x0:$lnk_header: 4C 00 00 00
    0x120:$powershell: powershell
    0x130:$iex: IEX
    0x140:$download: DownloadString

Remediation:
  1. Move file to quarantine
  2. Analyze with LNK parser
  3. Block file hash
  4. Hunt for similar files
  5. Investigate user who received it
================================================================================
*/


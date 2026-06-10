rule Ransomware_File_Patterns {
    meta:
        description = "Detects common ransomware file markers and encryption patterns"
        author = "Solomon James"
        date = "2026-06-10"
        mitre = "T1486, T1565.001"
        severity = "CRITICAL"
    strings:
        // Ransomware ransom notes
        $ransom1 = "decrypt" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "pay" nocase
        $ransom4 = "restore" nocase
        $ransom5 = "encrypted" nocase
        
        // File extensions (common ransomware)
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".ransomed" nocase
        $ext4 = ".crypted" nocase
        $ext5 = ".hacked" nocase
        
        // Conti/LockBit/REvil patterns
        $conti = "CONTI" nocase
        $lockbit = "LockBit" nocase
        $revil = "REvil" nocase
        
        // Entropy indicators (encrypted files)
        $high_entropy = /[\x00-\xFF]{1000,}/ // High entropy binary data
    condition:
        (any of ($ransom*) and any of ($ext*)) or 
        (any of ($conti, $lockbit, $revil)) or
        $high_entropy
}

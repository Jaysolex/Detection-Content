rule Malicious_LNK_File {
    meta:
        description = "Detects suspicious LNK file characteristics"
        author = "Solomon James"
        date = "2026-06-10"
        mitre = "T1547.009"
    strings:
        $lnk_header = { 4C 00 00 00 }
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase
    condition:
        $lnk_header at 0 and any of them
}

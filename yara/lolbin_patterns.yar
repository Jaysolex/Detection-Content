rule LOLBIN_Execution {
    meta:
        description = "Detects execution of living-off-the-land binaries"
        author = "Solomon James"
        mitre = "T1218"
    strings:
        $certutil = "certutil.exe" nocase
        $bitsadmin = "bitsadmin.exe" nocase
        $wmic = "wmic.exe" nocase
        $mshta = "mshta.exe" nocase
    condition:
        any of them
}

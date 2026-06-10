rule EMOTET_Trickbot_Malware {
    meta:
        description = "Detects Emotet and Trickbot malware signatures"
        author = "Solomon James"
        date = "2026-06-10"
        mitre = "T1566.001, T1204.002"
        severity = "CRITICAL"
    strings:
        // Emotet strings
        $emotet1 = "emotet" nocase
        $emotet2 = {4D 5A 90 00 03 00 00 00} // PE header + Emotet packer
        $emotet3 = "ws2_32.dll" wide
        $emotet4 = "wininet.dll" wide
        
        // Trickbot strings
        $trickbot1 = "trickbot" nocase
        $trickbot2 = "bot" nocase
        $trickbot3 = "config.ini" wide
        $trickbot4 = "server.txt" wide
        
        // Command & control indicators
        $c2_1 = /http:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+/
        $c2_2 = /https:\/\/[a-zA-Z0-9\-\.]+\.(com|net|org|ru|ua|by)/
    condition:
        (any of ($emotet*) or any of ($trickbot*)) and any of ($c2*)
}

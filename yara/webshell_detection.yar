rule Webshell_Detection {
    meta:
        description = "Detects common web shells (ASP, PHP, JSP)"
        author = "Solomon James"
        date = "2026-06-10"
        mitre = "T1190, T1505.003"
        severity = "CRITICAL"
    strings:
        // PHP webshells
        $php1 = "<?php" nocase
        $php2 = "eval(" nocase
        $php3 = "system(" nocase
        $php4 = "shell_exec(" nocase
        $php5 = "exec(" nocase
        
        // ASP webshells
        $asp1 = "<%@" nocase
        $asp2 = "CreateObject" nocase
        $asp3 = "WScript.Shell" nocase
        $asp4 = "cmd.exe" nocase
        
        // JSP webshells
        $jsp1 = "<%@" nocase
        $jsp2 = "Runtime.getRuntime()" nocase
        $jsp3 = "ProcessBuilder" nocase
        
        // Generic shell indicators
        $shell1 = "backdoor" nocase
        $shell2 = "cmd" nocase
        $shell3 = "command" nocase
        $shell4 = "upload" nocase
        $shell5 = "shell" nocase
        
        // Command execution patterns
        $cmd1 = /\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $cmd2 = /exec\s*\(/
        $cmd3 = /system\s*\(/
    condition:
        (any of ($php*) or any of ($asp*) or any of ($jsp*)) and 
        (any of ($shell*) or any of ($cmd*))
}

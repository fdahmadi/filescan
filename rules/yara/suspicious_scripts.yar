rule suspicious_powershell_download : suspicious
{
    meta:
        description = "PowerShell download cradle patterns"
        severity = "medium"
        author = "filescan"

    strings:
        $a1 = "DownloadString" nocase ascii
        $a2 = "DownloadFile" nocase ascii
        $a3 = "Invoke-Expression" nocase ascii
        $a4 = "IEX" ascii
        $a5 = "FromBase64String" nocase ascii
        $a6 = "System.Net.WebClient" nocase ascii

    condition:
        2 of them
}

rule suspicious_php_webshell : malware
{
    meta:
        description = "Common PHP webshell patterns"
        severity = "high"
        author = "filescan"

    strings:
        $s1 = "eval($_POST" nocase ascii
        $s2 = "eval($_GET" nocase ascii
        $s3 = "assert($_POST" nocase ascii
        $s4 = "base64_decode" nocase ascii
        $s5 = "shell_exec" nocase ascii
        $s6 = "passthru" nocase ascii
        $s7 = "system($_" nocase ascii

    condition:
        2 of ($s1, $s2, $s3, $s7) or (1 of ($s1, $s2, $s3, $s7) and 1 of ($s4, $s5, $s6))
}

rule suspicious_macro_autoopen : suspicious
{
    meta:
        description = "Office macro auto-execution markers in text dumps"
        severity = "medium"
        author = "filescan"

    strings:
        $a = "AutoOpen" ascii
        $b = "Document_Open" ascii
        $c = "Auto_Open" ascii
        $d = "Workbook_Open" ascii
        $e = "Shell(" ascii

    condition:
        1 of ($a, $b, $c, $d) and $e
}

rule office_macro_autoexec_shell : malware
{
    meta:
        description = "Office/VBA auto-exec plus shell or download markers"
        severity = "high"
        author = "filescan"

    strings:
        $auto1 = "AutoOpen" ascii
        $auto2 = "Auto_Open" ascii
        $auto3 = "Document_Open" ascii
        $auto4 = "Workbook_Open" ascii
        $auto5 = "Document_Close" ascii
        $shell1 = "Shell(" ascii
        $shell2 = "WScript.Shell" nocase ascii
        $shell3 = "CreateObject(" nocase ascii
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "Msxml2.XMLHTTP" nocase ascii
        $dl3 = "WinHttp.WinHttpRequest" nocase ascii
        $ps = "powershell" nocase ascii

    condition:
        1 of ($auto*) and (1 of ($shell*) or 1 of ($dl*) or $ps)
}

rule office_vba_obfuscation_markers : suspicious
{
    meta:
        description = "Heavy VBA string obfuscation / Chr concatenation"
        severity = "medium"
        author = "filescan"

    strings:
        $c1 = /Chr\(\d{1,3}\)\s*&\s*Chr\(\d{1,3}\)/ ascii
        $c2 = /Chr\$\(\d{1,3}\)/ ascii
        $x1 = "Xor" ascii
        $x2 = "StrReverse" nocase ascii
        $x3 = "UserForm" ascii
        $x4 = "Environ(" nocase ascii

    condition:
        (#c1 + #c2) >= 8 or (1 of ($c1, $c2) and 2 of ($x*))
}

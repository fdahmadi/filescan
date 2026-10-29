rule powershell_hidden_window_encoded : malware
{
    meta:
        description = "PowerShell hidden window + encoded / bypass patterns"
        severity = "high"
        author = "filescan"

    strings:
        $w = /-WindowStyle\s+Hidden/ nocase ascii
        $n = /-Nop(rofile)?/ nocase ascii
        $e = /-EncodedCommand/ nocase ascii
        $b = /-ExecutionPolicy\s+Bypass/ nocase ascii
        $i = "Invoke-Expression" nocase ascii
        $x = "IEX(" nocase ascii

    condition:
        ($w or $n or $b) and ($e or $i or $x)
}

rule batch_certutil_download : malware
{
    meta:
        description = "certutil download / decode living-off-the-land"
        severity = "high"
        author = "filescan"

    strings:
        $a = "certutil" nocase ascii
        $b = "-urlcache" nocase ascii
        $c = "-split" nocase ascii
        $d = "-decode" nocase ascii
        $e = "http://" nocase ascii
        $f = "https://" nocase ascii

    condition:
        $a and 1 of ($b, $c, $d) and 1 of ($e, $f)
}

rule vbs_wscript_download : suspicious
{
    meta:
        description = "VBScript download + run helpers"
        severity = "medium"
        author = "filescan"

    strings:
        $a = "WScript.Shell" nocase ascii
        $b = "MSXML2.XMLHTTP" nocase ascii
        $c = "ADODB.Stream" nocase ascii
        $d = "SaveToFile" nocase ascii
        $e = "Run(" nocase ascii

    condition:
        3 of them
}

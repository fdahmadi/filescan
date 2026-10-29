rule zip_js_dropper_markers : suspicious
{
    meta:
        description = "Archive/script dropper markers often seen with JS/VBS loaders"
        severity = "medium"
        author = "filescan"

    strings:
        $a = "ThisDocument" ascii
        $b = "ActiveDocument" ascii
        $c = ".jse" nocase ascii
        $d = ".vbe" nocase ascii
        $e = "Scripting.FileSystemObject" nocase ascii
        $f = "ADODB.Stream" nocase ascii
        $g = "SaveToFile" nocase ascii
        $h = "Type=1" ascii

    condition:
        3 of them
}

rule iso_lnk_execution_chain : suspicious
{
    meta:
        description = "ISO/LNK-style execution chain markers in extracted text"
        severity = "medium"
        author = "filescan"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $cmd = "cmd.exe" nocase ascii
        $ps = "powershell" nocase ascii
        $mshta = "mshta" nocase ascii
        $wscript = "wscript" nocase ascii
        $http = "http://" nocase ascii
        $https = "https://" nocase ascii

    condition:
        $lnk and 1 of ($cmd, $ps, $mshta, $wscript) and 1 of ($http, $https)
}

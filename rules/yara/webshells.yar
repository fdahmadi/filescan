rule webshell_php_eval_request : malware
{
    meta:
        description = "PHP eval on request superglobals"
        severity = "high"
        author = "filescan"

    strings:
        $e1 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $e2 = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $e3 = /create_function\s*\(/ nocase
        $e4 = /preg_replace\s*\(\s*['\"]\/.+\/e['\"]/ nocase

    condition:
        any of them
}

rule webshell_php_system_tools : malware
{
    meta:
        description = "PHP remote command execution helpers"
        severity = "high"
        author = "filescan"

    strings:
        $a = "shell_exec" nocase ascii
        $b = "passthru" nocase ascii
        $c = "proc_open" nocase ascii
        $d = "pcntl_exec" nocase ascii
        $e = "$_GET" ascii
        $f = "$_POST" ascii
        $g = "base64_decode" nocase ascii

    condition:
        2 of ($a, $b, $c, $d) and 1 of ($e, $f) and $g
}

rule webshell_aspx_process : malware
{
    meta:
        description = "ASP.NET process start patterns"
        severity = "high"
        author = "filescan"

    strings:
        $a = "ProcessStartInfo" ascii
        $b = "cmd.exe" nocase ascii
        $c = "FromBase64String" ascii
        $d = "System.Diagnostics.Process" ascii

    condition:
        2 of them
}

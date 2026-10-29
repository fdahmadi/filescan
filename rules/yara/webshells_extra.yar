rule webshell_php_assert_callback : malware
{
    meta:
        description = "PHP assert / create_function / preg_replace /e webshell style"
        severity = "high"
        author = "filescan"

    strings:
        $a = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /preg_replace\s*\([^)]*\/e/ nocase
        $c = "create_function" nocase ascii
        $d = /call_user_func\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $e = /array_map\s*\(\s*\$_(GET|POST)/ nocase

    condition:
        1 of them
}

rule webshell_jsp_runtime_exec : malware
{
    meta:
        description = "JSP Runtime.exec command execution"
        severity = "high"
        author = "filescan"

    strings:
        $a = "Runtime.getRuntime().exec" ascii
        $b = "ProcessBuilder" ascii
        $c = "request.getParameter" ascii
        $d = "javax.servlet" ascii

    condition:
        $a and 1 of ($b, $c, $d)
}

rule webshell_aspx_eval_compile : malware
{
    meta:
        description = "ASP.NET dynamic compile / eval style markers"
        severity = "high"
        author = "filescan"

    strings:
        $a = "System.Reflection.Assembly" ascii
        $b = "CompileAssemblyFromSource" ascii
        $c = "Eval(" ascii
        $d = "Request[" ascii
        $e = "FromBase64String" ascii

    condition:
        2 of ($a, $b, $c, $e) and $d
}

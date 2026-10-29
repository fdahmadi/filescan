import "elf"

rule elf_packed_upx_section : suspicious
{
    meta:
        description = "ELF with UPX-style section names"
        severity = "medium"
        author = "filescan"

    condition:
        elf.number_of_sections > 0 and
        for any i in (0..elf.number_of_sections - 1): (
            elf.sections[i].name == "UPX0" or
            elf.sections[i].name == "UPX1" or
            elf.sections[i].name == "UPX2"
        )
}

rule linux_reverse_shell_strings : malware
{
    meta:
        description = "Common Linux reverse-shell / backdoor strings"
        severity = "high"
        author = "filescan"

    strings:
        $a = "/bin/bash -i" ascii
        $b = "/bin/sh -i" ascii
        $c = "bash -i >& /dev/tcp/" ascii
        $d = "nc -e /bin/sh" ascii
        $e = "ncat -e /bin/sh" ascii
        $f = "python -c 'import socket" ascii
        $g = "setsockopt(SOL_SOCKET, SO_REUSEADDR" ascii
        $h = "iptables -F" ascii
        $i = "curl|" ascii
        $j = "wget|" ascii

    condition:
        2 of them
}

import "pe"

rule pe_suspicious_imports_combo : suspicious
{
    meta:
        description = "PE imports often used for injection / remote thread"
        severity = "medium"
        author = "filescan"

    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}

rule pe_upsx_section_name : suspicious
{
    meta:
        description = "PE section name commonly used by UPX packer"
        severity = "medium"
        author = "filescan"

    condition:
        pe.is_pe and
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == "UPX0" or
            pe.sections[i].name == "UPX1" or
            pe.sections[i].name == ".UPX"
        )
}

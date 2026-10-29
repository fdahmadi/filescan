# Manual check — scan results (recorded)

Live API run: `sensitivity=balanced`, `use_remote_intel=true`.

Samples under `should_detect/` are **EICAR + synthetic patterns / crafted executables**, not live malware downloads from the internet.

| File | Intent folder | Verdict | Match? | Notable engines | MIME | s |
|------|---------------|---------|--------|-----------------|------|---|
| `clean/config.json` | `clean` | **suspicious** | `noise_or_fp` | oletools:suspicious (suspicious:Suspicious|Base64 Strings|Base64-encoded strings were detected, may be used to obfuscate strings (option --decode to see all)) | `application/json` | 0.01 |
| `clean/contacts.csv` | `clean` | **suspicious** | `noise_or_fp` | oletools:suspicious (vba_macros_present) | `text/csv` | 0.01 |
| `clean/linux_hello_elf` | `clean` | **clean** | `ok` | oletools:error | `application/x-pie-executable` | 0.01 |
| `clean/logo.png` | `clean` | **clean** | `ok` | — | `image/png` | 0.01 |
| `clean/notes.txt` | `clean` | **clean** | `ok` | — | `text/plain` | 0.01 |
| `clean/photo.jpg` | `clean` | **clean** | `ok` | — | `image/jpeg` | 0.01 |
| `clean/windows_tiny_pe.exe` | `clean` | **suspicious** | `noise_or_fp` | precheck:suspicious (dangerous_extension:.exe); oletools:error; capa:error | `application/vnd.microsoft.portable-executable` | 0.02 |
| `should_detect/certutil_fetch.cmd` | `should_detect` | **malicious** | `ok` | precheck:suspicious (dangerous_extension:.cmd, extension_mime_mismatch:.cmd->text/x-msdos-batch); yara:matched (Certutil_Decode_OR_Download, batch_certutil_download [malware]); oletools:suspicious (ioc:IOC|https://example.invalid/payload.bin|URL, ioc:IOC|p.exe|Executable file name) | `text/x-msdos-batch` | 0.02 |
| `should_detect/download_cradle.ps1` | `should_detect` | **malicious** | `ok` | precheck:suspicious (dangerous_extension:.ps1, extension_mime_mismatch:.ps1->text/plain); yara:matched (powershell_download_cradle [malware], suspicious_powershell_download [suspicious]); oletools:suspicious (suspicious:Suspicious|PowerShell|May run PowerShell commands, suspicious:Suspicious|New-Object|May create an OLE object using PowerShell) | `text/plain` | 0.02 |
| `should_detect/eicar_test.exe` | `should_detect` | **malicious** | `ok` | clamav:infected (Eicar-Test-Signature); yara:matched (eicar_test_file [malware]); capa:error | `text/plain` | 0.02 |
| `should_detect/eicar_test.txt` | `should_detect` | **malicious** | `ok` | clamav:infected (Eicar-Test-Signature); yara:matched (eicar_test_file [malware]); capa:error | `text/plain` | 0.02 |
| `should_detect/jsp_exec.jsp` | `should_detect` | **malicious** | `ok` | precheck:suspicious (dangerous_extension:.jsp); yara:matched (EXT_WEBSHELL_JSP_Generic_Tiny, WEBSHELL_JSP_Generic); oletools:suspicious (suspicious:Suspicious|exec|May run an executable file or a system command using Excel 4 Macros (XLM/XLF)) | `text/plain` | 0.02 |
| `should_detect/linux_upx_sections_elf` | `should_detect` | **suspicious** | `ok` | yara:suspicious (elf_packed_upx_section [suspicious]); oletools:error; capa:error | `application/x-executable` | 0.01 |
| `should_detect/office_macro_markers.txt` | `should_detect` | **malicious** | `ok` | yara:matched (office_macro_autoexec_shell [malware], suspicious_macro_autoopen [suspicious]) | `text/plain` | 0.02 |
| `should_detect/webshell_eval.php` | `should_detect` | **malicious** | `ok` | precheck:suspicious (dangerous_extension:.php); yara:matched (EXT_WEBSHELL_PHP_Generic, WEBSHELL_PHP_Generic_Eval); oletools:suspicious (vba_macros_present) | `text/x-php` | 0.02 |
| `should_detect/windows_upx_section.exe` | `should_detect` | **suspicious** | `ok` | precheck:suspicious (dangerous_extension:.exe); yara:suspicious (pe_upsx_section_name [suspicious]); oletools:error; capa:error | `application/vnd.microsoft.portable-executable` | 0.02 |

### Match legend

- `ok` — outcome matches folder intent
- `noise_or_fp` — clean folder but non-clean verdict (oletools / `.exe` precheck, etc.)
- `miss` — should_detect but not suspicious/malicious

### Executables included

| File | What it is |
|------|------------|
| `clean/linux_hello_elf` | Real Linux x86_64 ELF (`gcc` hello) — should be clean |
| `clean/windows_tiny_pe.exe` | Tiny crafted PE32 (harmless stub) — may be **suspicious** only for `.exe` extension policy |
| `should_detect/linux_upx_sections_elf` | ELF with `UPX0`/`UPX1` sections — YARA packed-ELF heuristic |
| `should_detect/windows_upx_section.exe` | PE with `UPX0` section name — YARA PE/UPX heuristic |
| `should_detect/eicar_test.exe` | EICAR test string named `.exe` — ClamAV + YARA |


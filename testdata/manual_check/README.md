# Manual check pack (safe samples)

Folder for **hands-on** testing in the demo UI or API.

**Employer-facing write-up (catalog + explanations + results):**  
[../../docs/TEST_SAMPLES.en.md](../../docs/TEST_SAMPLES.en.md)

## Safety policy

| Kind | What we put here |
|------|------------------|
| “Malicious” demos | **EICAR** (official AV test string) + **synthetic** snippets that look like webshells / PS cradles / LOLBAS **in text form** |
| Real malware from the internet | **Not downloaded** into this repo (unsafe on a workstation; use a lab VM if you ever need live samples) |

These files are for verifying FileScan wiring — not for studying live implants.

## Layout

```
manual_check/
  clean/           # intended benign files
  should_detect/   # intended detections
  SCAN_RESULTS.md  # last run against the live API
  scan_results.json
  README.md
```

## How to test

1. Stack up: `docker compose ps` / http://127.0.0.1:8001/ui/  
2. Upload files from `clean/` then `should_detect/`  
3. Or re-scan everything and refresh the report (from repo root):

```bash
# example one-liner for EICAR
curl -sS -H "X-API-Key: dev-demo-key" \
  -F "file=@testdata/manual_check/should_detect/eicar_test.txt" \
  -F "sensitivity=balanced" -F "use_remote_intel=true" \
  http://127.0.0.1:8001/v1/scan | jq '{verdict, engines: [.engines[] | {name, status, threats}]}'
```

## Expected intent vs last measured results

See **[SCAN_RESULTS.md](SCAN_RESULTS.md)** for the machine-recorded verdicts from a live run.

Rough expectations (`balanced` + remote intel on):

| Path | Intent | Typical outcome |
|------|--------|-----------------|
| `clean/notes.txt` | clean | clean |
| `clean/logo.png` | clean | clean |
| `clean/photo.jpg` | clean | clean |
| `clean/config.json` | clean | may be **suspicious** via oletools FP on short JSON |
| `clean/contacts.csv` | clean | may be **suspicious** via oletools FP |
| `should_detect/eicar_test.txt` | detect | **malicious** (ClamAV + YARA) |
| `should_detect/webshell_eval.php` | detect | **malicious** (YARA) |
| `should_detect/download_cradle.ps1` | detect | **malicious** (YARA) |
| `should_detect/jsp_exec.jsp` | detect | **malicious** (YARA) |
| `should_detect/certutil_fetch.cmd` | detect | **malicious** (YARA) |
| `should_detect/office_macro_markers.txt` | detect | **malicious** (YARA) |
| `clean/linux_hello_elf` | clean Linux ELF | **clean** |
| `clean/windows_tiny_pe.exe` | tiny PE stub | often **suspicious** only from precheck `dangerous_extension:.exe` |
| `should_detect/linux_upx_sections_elf` | ELF + UPX section names | **suspicious** (YARA) |
| `should_detect/windows_upx_section.exe` | PE + UPX0 section | **suspicious** (YARA) |
| `should_detect/eicar_test.exe` | EICAR as `.exe` | **malicious** (ClamAV + YARA) |

Oletools false positives on some benign text-like files, and precheck treating `.exe` as a dangerous extension, are useful demo points for **sensitivity** and policy noise.

## Executables (safe)

| File | Type |
|------|------|
| `clean/linux_hello_elf` | Real `gcc`-built Linux x86_64 executable (“hello”) |
| `clean/windows_tiny_pe.exe` | Minimal crafted PE32 (not malware; stub `ret`) |
| `should_detect/linux_upx_sections_elf` | Crafted ELF with `UPX0`/`UPX1` sections for packer YARA |
| `should_detect/windows_upx_section.exe` | Crafted PE with section name `UPX0` |
| `should_detect/eicar_test.exe` | Official EICAR antivirus test string with `.exe` name |

No live trojan/virus binaries were downloaded from the internet.

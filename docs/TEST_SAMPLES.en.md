# FileScan — Test samples pack (for employer review)

This document describes the **safe test files** we built for demos, what each one is for, and **what FileScan returned** when we scanned them on the running stack.

| | |
|--|--|
| Files location | [`testdata/manual_check/`](../testdata/manual_check/) |
| Machine-recorded table | [`testdata/manual_check/SCAN_RESULTS.md`](../testdata/manual_check/SCAN_RESULTS.md) |
| Demo UI | http://127.0.0.1:8001/ui/ |
| Scan settings used for the recorded run | `sensitivity=balanced`, `use_remote_intel=true` |

Related: [DEMO.en.md](DEMO.en.md) · [STATUS.en.md](STATUS.en.md) · [CORE_DETECTION.en.md](CORE_DETECTION.en.md)

---

## 1) Important safety note (please read)

| We included | We did **not** include |
|-------------|-------------------------|
| Official **EICAR** antivirus test string | Live malware / trojans downloaded from the internet |
| **Synthetic** text patterns (webshell-like PHP/JSP, PowerShell cradle, certutil LOLBAS-style lines, Office macro markers) | Weaponized implants or packed real samples |
| **Crafted** tiny Windows PE stubs and a Linux ELF with fake UPX section names | Production malware corpora |

**Why:** putting real malware on a normal workstation or in git is unsafe. EICAR + synthetic patterns are enough to prove ClamAV, YARA, precheck, and policy behavior for a pilot demo.

If a lab later needs live samples, that should be done only in an isolated VM with a clear chain of custody (e.g. MalwareBazaar under research ToS) — outside this pack.

---

## 2) Folder layout

```
testdata/manual_check/
  clean/              # intended benign files
  should_detect/      # intended detections
  README.md           # short pack guide
  SCAN_RESULTS.md     # last live API results
  scan_results.json   # same data as JSON
```

| Folder | Intent |
|--------|--------|
| `clean/` | Prefer verdict **clean** (some soft noise is expected — see below) |
| `should_detect/` | Prefer **malicious** or at least **suspicious** |

---

## 3) What each sample is

### 3.1 Clean / benign

| File | What it is | Why it is here |
|------|------------|----------------|
| `clean/notes.txt` | Plain text notes | Ordinary document |
| `clean/logo.png` | Tiny 1×1 PNG | Image type |
| `clean/photo.jpg` | Tiny JPEG | Image type |
| `clean/config.json` | Small JSON config | App-like text |
| `clean/contacts.csv` | Simple CSV | Spreadsheet-like text |
| `clean/linux_hello_elf` | Real Linux x86_64 ELF built with `gcc` (“hello”) | Clean native Linux executable |
| `clean/windows_tiny_pe.exe` | Minimal crafted PE32 (harmless `ret` stub) | Clean-ish Windows executable shape |

### 3.2 Should detect (safe “bad” demos)

| File | What it is | Why it is here |
|------|------------|----------------|
| `should_detect/eicar_test.txt` | Official EICAR test string | Industry-standard AV proof (ClamAV) |
| `should_detect/eicar_test.exe` | Same EICAR bytes, `.exe` name | Shows detection by content, not only extension |
| `should_detect/webshell_eval.php` | Synthetic PHP `eval($_GET…)` pattern | Webshell-style YARA |
| `should_detect/jsp_exec.jsp` | Synthetic JSP `Runtime.exec` pattern | Java webshell-style YARA |
| `should_detect/download_cradle.ps1` | Synthetic PowerShell download+IEX cradle | Script malware-style YARA |
| `should_detect/certutil_fetch.cmd` | Synthetic certutil download/decode lines | LOLBAS-style YARA |
| `should_detect/office_macro_markers.txt` | AutoOpen + Shell markers as text | Macro-abuse YARA |
| `should_detect/linux_upx_sections_elf` | Crafted ELF with sections named `UPX0` / `UPX1` | Packer heuristic (YARA), not real UPX malware |
| `should_detect/windows_upx_section.exe` | Crafted PE with section name `UPX0` | PE packer heuristic (YARA) |

---

## 4) Recorded scan results (summary)

Full engine detail: [SCAN_RESULTS.md](../testdata/manual_check/SCAN_RESULTS.md).

### Clean folder

| File | Verdict | Comment for stakeholders |
|------|---------|---------------------------|
| `notes.txt` | **clean** | As expected |
| `logo.png` | **clean** | As expected |
| `photo.jpg` | **clean** | As expected |
| `linux_hello_elf` | **clean** | Real Linux binary stayed clean |
| `config.json` | **suspicious** | Soft noise from **oletools** on short JSON (false positive / noisy heuristic) |
| `contacts.csv` | **suspicious** | Soft noise from **oletools** on CSV |
| `windows_tiny_pe.exe` | **suspicious** | Mostly **precheck** flagging `.exe` as a dangerous extension — policy signal, not “known virus” |

These “noise” cases are useful in a demo: they show why **sensitivity** (`lenient` / `balanced` / `strict`) and reading **per-engine** rows matter, not only the single verdict word.

### Should-detect folder

| File | Verdict | Main signal |
|------|---------|-------------|
| `eicar_test.txt` | **malicious** | ClamAV `Eicar-Test-Signature` + YARA |
| `eicar_test.exe` | **malicious** | Same |
| `webshell_eval.php` | **malicious** | YARA webshell rules |
| `jsp_exec.jsp` | **malicious** | YARA webshell rules |
| `download_cradle.ps1` | **malicious** | YARA PowerShell rules |
| `certutil_fetch.cmd` | **malicious** | YARA certutil / LOLBAS-style rules |
| `office_macro_markers.txt` | **malicious** | YARA Office/macro markers |
| `linux_upx_sections_elf` | **suspicious** | YARA `elf_packed_upx_section` |
| `windows_upx_section.exe` | **suspicious** | YARA `pe_upsx_section_name` (+ `.exe` precheck) |

**Match rate for this pack:** all `should_detect` samples hit **malicious** or **suspicious** as intended. Clean images/text/ELF behaved well; a few clean text/PE cases show soft engine noise (documented above).

---

## 5) How the employer can re-check

1. Start stack: `docker compose up -d`  
2. Open http://127.0.0.1:8001/ui/ (API key `dev-demo-key`)  
3. Upload from `testdata/manual_check/clean/` then `should_detect/`  
4. Optionally uncheck **Use remote hash intel** for local-only runs (hash is never a full file upload either way)

Or via API:

```bash
curl -sS -H "X-API-Key: dev-demo-key" \
  -F "file=@testdata/manual_check/should_detect/eicar_test.txt" \
  -F "sensitivity=balanced" \
  -F "use_remote_intel=true" \
  http://127.0.0.1:8001/v1/scan | jq '{verdict, sensitivity, use_remote_intel, engines: [.engines[] | {name, status, threats}]}'
```

---

## 6) Talking points for the meeting

1. **Multi-engine:** ClamAV catches EICAR; YARA catches webshell/script/packer heuristics; precheck flags risky extensions.  
2. **Safe demos:** no need to bring live malware into the room for a first pilot.  
3. **Executables covered:** Linux ELF + Windows PE shapes are in the pack.  
4. **Noise is visible and controllable:** oletools / `.exe` policy can raise `suspicious`; sensitivity and remote-intel checkbox let you tune the story.  
5. **Remote intel is optional:** abuse.ch/YARAify only get a **hash** when enabled; users can disable per scan.

---

## 7) Related smaller corpus

Automated offline table (YARA-focused bench script): [`testdata/corpus/`](../testdata/corpus/) · `scripts/benchmark_corpus.py`.  
The **manual_check** pack above is the one meant for stakeholder walkthroughs in the UI.

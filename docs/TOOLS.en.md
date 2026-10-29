# FileScan — Tools & libraries catalog

What each scanner, CLI tool, and Python library does in this project, and how FileScan uses it.

Project status: [STATUS.en.md](STATUS.en.md) · Related: [ARCHITECTURE.en.md](ARCHITECTURE.en.md) · [CORE_DETECTION.en.md](CORE_DETECTION.en.md) · [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md)

---

## 1) Scan engines (detection)

These appear as named engines in `/v1/health` and `/v1/scan` results.

| Engine name | Tool / product | Cost | Runs where |
|-------------|----------------|------|------------|
| `clamav` | ClamAV (`clamd`) | Free | Separate Compose service |
| `yara` | YARA (+ our / community rules) | Free | Inside API process |
| `precheck` | Our heuristics (entropy, policy) | Free | Inside API |
| `oletools` | oletools (olevba, …) | Free | Inside API (pip) |
| `lmd` | Linux Malware Detect (`maldet`) | Free | Inside API image |
| `capa` | Mandiant CAPA (`flare-capa`) | Free | Inside API image |
| `floss` | Mandiant FLOSS (`flare-floss`) | Free | Inside API image |
| `pefile` | `pefile` (Python PE parser) | Free | Inside API (pip) |
| `abusech` | abuse.ch MalwareBazaar API | Free Auth-Key | Remote HTTPS (hash only) |
| `yaraify` | abuse.ch YARAify API | Free Auth-Key | Remote HTTPS (hash only) |

### ClamAV (`clamav`)

**What it is:** Open-source antivirus engine. Maintains a signature database and a daemon (`clamd`) that scans files/streams.

**What it does for us:** Classic AV detection (viruses, many known malware families, EICAR test file). FileScan talks to `clamd` over **TCP INSTREAM** (bytes of the upload are streamed; we do not shell out to `clamscan`).

**Install:** Docker image `clamav/clamav:1.4` in Compose. Signatures update via `freshclam` inside that image.

**Code:** `app/engines/clamav.py`

---

### YARA (`yara`)

**What it is:** A pattern-matching language and engine for describing malware (byte sequences, strings, PE/ELF structure, conditions).

**What it does for us:** Applies first-party rules under `rules/yara/` plus optional community rules under `rules/yara/community/`. Matches can be tagged `malware` / `suspicious` and feed the verdict.

**Install:** Python binding `yara-python` (and system `libyara`). Rules are plain `.yar` files; compiled at API startup.

**Helpers:** `scripts/fetch_community_yara.sh` (opt-in curated Neo23x0 subset).

**Code:** `app/engines/yara_engine.py`

---

### Precheck (`precheck`)

**What it is:** Our own lightweight heuristics — not a third-party product.

**What it does for us:** Cheap signals before heavier engines (e.g. high entropy that often means packing/encryption, dangerous extensions, extension↔MIME mismatch, double-extension disguises like `photo.png.exe`). Flags **benign-looking names** (`.png` / `.jpg` / `.pdf` / …) whose content is actually PE/ELF. Helps mark `suspicious` without claiming a malware family name. Also re-runs on **extracted ZIP/TAR members** (same as ClamAV/YARA/…).

**Code:** `app/engines/precheck.py` · entropy helper `app/services/entropy.py`

---

### pefile (`pefile`)

**What it is:** Widely used Python library to parse Windows Portable Executable (PE) files (headers, sections, imports, resources, overlay).

**What it does for us:** Soft PE structure heuristics — large overlay, writable+executable sections, TLS callbacks, empty import tables (on larger files), and embedded `MZ` blobs in resources. Icon/PNG resource counts are reported in **details** only (too common on legitimate apps to raise a verdict alone). Complements CAPA without claiming a malware family.

**Install:** `pip install pefile` (in `requirements.txt`).

**Code:** `app/engines/pefile_engine.py`

---

### oletools (`oletools`)

**What it is:** Python toolkit for analyzing Microsoft Office files (OLE/OOXML), especially VBA macros (`olevba` and related).

**What it does for us:** Flags auto-exec macros, suspicious VBA, and related Office abuse. Skips clearly non-Office suffixes.

**Install:** `pip install oletools` (in `requirements.txt`).

**Code:** `app/engines/oletools_engine.py`

---

### Linux Malware Detect — LMD (`lmd`)

**What it is:** Free Linux/server malware scanner focused on web shells and shared-hosting threats. CLI: `maldet`. Uses its own signature set (MD5 / hex / YARA-style packs).

**What it does for us:** Extra coverage for PHP/CGI/web malware that general AV may miss.

**Install:** Best-effort in the API Dockerfile from upstream LMD tarball; binary `maldet` on PATH.

**Code:** `app/engines/lmd.py`

---

### CAPA (`capa`)

**What it is:** Mandiant FLARE tool that reports **capabilities** of an executable (e.g. persistence, injection, C2-like behavior) by matching a large free rule set — not a traditional “virus name” AV.

**What it does for us:** Labels PE (and supported formats) with capability hits; high-risk namespaces can raise `suspicious` / `matched`. Needs **capa-rules** (bundled into the Docker image at `/opt/capa-rules`).

**Install:** `pip install flare-capa` + rules from [mandiant/capa-rules](https://github.com/mandiant/capa-rules).

**Code:** `app/engines/capa_engine.py`

---

### FLOSS (`floss`)

**What it is:** Mandiant FLARE **FLARE Obfuscated String Solver**. Extracts static, stack, tight, and decoded strings from binaries (including strings that malware builds or decrypts at runtime).

**What it does for us:** Scans PE/ELF/Mach-O; if recovered strings hit high-risk tokens (`powershell`, `VirtualAllocEx`, reverse-shell patterns, …), reports `suspicious` / `matched`. Skips plain text and non-binaries.

**Install:** `pip install flare-floss` (best-effort in Dockerfile).

**Code:** `app/engines/floss_engine.py`

---

### abuse.ch MalwareBazaar (`abusech`)

**What it is:** Community malware sample / intel platform by abuse.ch. Free research Auth-Key.

**What it does for us:** **Hash-only** lookup (`get_info`) — we never upload the file. If SHA256 is known malware, engine reports a hit.

**Config:** `FILESCAN_ABUSECH_AUTH_KEY`

**Domains:**

| URL | Role |
|-----|------|
| https://auth.abuse.ch/ | **Get Auth-Key** (required for these engines) |
| https://bazaar.abuse.ch/ | MalwareBazaar UI |
| https://mb-api.abuse.ch/api/v1 | API used by FileScan (`FILESCAN_ABUSECH_API_URL`) |

**Code:** `app/engines/abusech.py`

---

### YARAify (`yaraify`)

**What it is:** abuse.ch service that indexes YARA (and related) hits for known samples.

**What it does for us:** **Hash-only** lookup. Reuses the abuse.ch Auth-Key unless `FILESCAN_YARAIFY_AUTH_KEY` is set separately.

**Domains:**

| URL | Role |
|-----|------|
| https://auth.abuse.ch/ | Same Auth-Key portal |
| https://yaraify.abuse.ch/ | YARAify UI |
| https://yaraify-api.abuse.ch/api/v1 | API used by FileScan (`FILESCAN_YARAIFY_API_URL`) |

**Code:** `app/engines/yaraify.py`

---

## 2) Supporting libraries (not separate engines)

| Library / tool | Role in FileScan |
|----------------|------------------|
| **FastAPI** | HTTP API framework (`/v1/scan`, `/v1/health`, OpenAPI `/docs`) |
| **Uvicorn** | ASGI server that runs the FastAPI app |
| **Pydantic / pydantic-settings** | Request/response models + `FILESCAN_*` config from env |
| **python-multipart** | Multipart file upload parsing |
| **httpx** | HTTP client for abuse.ch / YARAify |
| **python-magic** (`libmagic`) | MIME type detection for intake policy |
| **aiofiles** | Async file helpers where used |
| **ssdeep** (optional) | Fuzzy hash — similar files share similar digests |
| **tlsh** / **pytlsh** (optional) | Another fuzzy hash (Trend Micro locality-sensitive hash) |
| **zipfile / tarfile** (stdlib) | Controlled archive expansion (nested depth, size limits) |

Fuzzy matching compares new uploads to denylist refs and previously cached malicious samples (`app/services/fuzzy_match.py`).

MIME allow/deny policy: `app/services/mime_policy.py` (uses magic MIME strings).

---

## 3) Rule packs & signature sources

| Source | Type | Notes |
|--------|------|--------|
| `rules/yara/*.yar` | First-party YARA | EICAR, scripts, webshells, PE/ELF heuristics, Office, droppers |
| `rules/yara/community/` | Third-party YARA | Curated Neo23x0 subset; review license before production |
| ClamAV CVD / daily | AV signatures | Updated by `freshclam` in ClamAV container |
| LMD signature pack | Web/Linux malware | Updated by LMD `sigup` during image install / runtime |
| `/opt/capa-rules` | CAPA capability rules | Fetched at Docker build from mandiant/capa-rules |

---

## 4) Local completion knobs (no external SaaS)

| Knob | What it does |
|------|----------------|
| **Sensitivity** | `lenient` / `balanced` / `strict` — how soft engines (CAPA, FLOSS, precheck, pefile, archive) escalate the final verdict |
| **Allow/deny lists** | Local SHA256 lists; optional fuzzy refs |
| **YARA rules** | First-party + `rules/yara/community/` |
| **Corpus benchmark** | `testdata/corpus` + `scripts/benchmark_corpus.py` — offline regression table |

abuse.ch / YARAify remain **optional** remote hash lookups (free Auth-Key). The core works without them.

## 5) Intentionally not used yet (documented deferred)

Still free, but **not** integrated on purpose for the pilot:

| Tool | Why deferred | Revisit when |
|------|----------------|--------------|
| **ExifTool** | Weak verdict signal for most malware pilots | Metadata-focused requirements appear |
| **Loki / Paranoya** | Extra IOC/YARA sidecar; overlap with YARA + LMD | Need a second dedicated IOC service |
| **Extra ClamAV community feeds** | License/trust review before mounting | Legal/trust OK |
| **abuse.ch / YARAify on archive members** | Outer-file hash only today; per-member HTTPS lookups × N hit fair-use / latency | Need known-malware-in-zip coverage and a member lookup budget |
| **VirusTotal / MetaDefender / paid AV** | Cloud or license cost | Employer budget / coverage gap |

Details: [NEXT_PATHS.en.md](NEXT_PATHS.en.md) · [ROADMAP.en.md](ROADMAP.en.md) · [CORE_DETECTION.en.md](CORE_DETECTION.en.md)

---

## 5b) Evaluated and not adopted as a scan engine

Reviewed for FileScan; **wrong tool class** for upload verdicts (kept here so the decision is visible to the team / employer).

### Exploit-DB / SearchSploit

| | |
|--|--|
| **What it is** | Official public archive of exploits, shellcodes, and PoCs (Offensive Security), plus the local `searchsploit` search CLI |
| **Repo** | https://gitlab.com/exploit-database/exploitdb (related: `exploitdb-bin-sploits`, `exploitdb-papers`) |
| **Audience** | Penetration testers and vulnerability researchers — lookup “is there a public exploit for X?”, not “is this uploaded file malware?” |
| **License** | GPL-2.0+ |

**Why not a FileScan engine**

- FileScan answers: *is this file malicious / suspicious / clean?* Exploit-DB answers: *what public exploits exist for a product/CVE?*
- Matching uploads against exploit/PoC trees is noisy (false positives), heavy to store/update, and overlaps poorly with ClamAV / YARA / LMD / abuse.ch.
- Binary/exploit packs can contain **live attack material** — conflicts with our safe-sample / no-live-malware pilot policy ([TEST_SAMPLES.en.md](TEST_SAMPLES.en.md)).

**Optional later (not detection)**

| Use | Notes |
|-----|--------|
| Report enrichment | If CAPA/YARA already surfaces a CVE, link Exploit-DB / searchsploit as a **reference only** (no file match) |
| Offline research | Analyst runs `searchsploit` on a separate host; not inside the API scan path |
| Signature research | Rare PoCs as inspiration for first-party YARA — never wire the full DB into `/v1/scan` |

**Do not:** clone Exploit-DB into the API image, scan uploads against it, or ship exploit binaries in `testdata/`.

---

## 5c) Candidate free / open-source additions (employer pick)

The pilot core is **usable without these**. They fill coverage gaps that current engines only partly address. All are free/OSS (or free public APIs). We add them later **only if the employer chooses** a gap — same `ScanEngine` adapter pattern as today.

Related status: [STATUS.en.md](STATUS.en.md) · [NEXT_PATHS.en.md](NEXT_PATHS.en.md) · [ROADMAP.en.md](ROADMAP.en.md)

### Suggested pick order

| Priority | Candidate | Gap it fills | Overlap with today | Effort |
|----------|-----------|--------------|--------------------|--------|
| ~~1~~ | ~~Stronger `precheck`~~ | ~~image / safe extension disguise~~ | **Done** — see Precheck above | — |
| ~~2~~ | ~~`pefile`~~ | ~~PE overlay / W+X / embedded MZ~~ | **Done** — engine `pefile` | — |
| **1** | **Detect It Easy (DiE)** | Packer / compiler / true type identification | Soft; complements CAPA + entropy precheck | Medium (CLI in image) |
| **2** | **Manalyze** | Suspicious PE indicators (imports, anomalies) | Some overlap with CAPA / `pefile`; cheaper static triage | Medium |
| **3** | **pdfid / pdf-parser** (Didier Stevens) or **peepdf** | Malicious PDF (JS, auto-actions, embedded files) | oletools covers Office, **not** PDF | Medium |
| **4** | **binwalk** | Embedded / carved payloads inside other files | Archives already handled; helps polyglots & firmware-style embeds | Medium |

### Medium priority (after the table above)

| Candidate | Gap | Notes |
|-----------|-----|--------|
| **ThreatFox** (abuse.ch) | Extra free IOC / hash intel | Same Auth-Key family as MalwareBazaar; hash-only; no file upload |
| **YARA-X** | Newer YARA engine | Migration cost; only if rule performance / features demand it |
| **NSRL** (known-good hashes) | Fewer false positives on common system binaries | Large DB; ops cost |
| **Extra ClamAV community feeds** | Broader AV signatures | Already deferred — license/trust review first ([§5](#5-intentionally-not-used-yet-documented-deferred)) |

### Not recommended as next engines

| Candidate | Why skip for now |
|-----------|------------------|
| **ExifTool** | Weak malware verdict signal (still listed under deferred metadata cases) |
| **Loki / Paranoya** | Heavy; overlaps YARA + LMD |
| **radare2 / Ghidra** | Reverse-engineering frameworks — too heavy for upload verdicts |
| **Strelka / MalwareMultiScan** | Full alternate platforms — would replace our architecture, not plug in lightly |
| **Exploit-DB** | Wrong tool class — see [§5b](#5b-evaluated-and-not-adopted-as-a-scan-engine) |

### How we would add a pick

1. Employer selects one row from the priority table (or medium list).  
2. We add a `ScanEngine` adapter + health check + unit/corpus samples.  
3. Soft vs hard verdict role is decided per tool (most of the above are **soft** / `suspicious` unless a clear hard hit exists).  
4. Docs (`STATUS`, this catalog) updated when the engine ships.

---

## 6) Quick map: tool → FileScan piece

```text
Upload
  │
  ├─ python-magic ──► MIME policy
  ├─ SHA256 / ssdeep / tlsh ──► cache + allow/deny + fuzzy
  ├─ precheck (entropy / extension / MIME / disguise)
  ├─ clamav  ──TCP──► clamd
  ├─ yara    ──rules/yara (+ community)
  ├─ oletools
  ├─ maldet (LMD)
  ├─ capa (+ capa-rules)
  ├─ floss
  ├─ pefile (PE overlay / W+X / resources)
  ├─ archive extract ──► re-scan members with precheck + clamav + yara + oletools + lmd + capa + floss + pefile
  ├─ abuse.ch / YARAify ──HTTPS hash lookup on outer file only (optional key)
  └─ orchestrator ──► verdict (clean / suspicious / malicious)
```

---

## 7) License & ops notes

- Prefer **self-hosted** free tools for private files; cloud engines are hash-only or opt-in later.
- Community YARA and extra Clam feeds: always check **license** and false-positive risk before production.
- Optional pip tools (`flare-capa`, `flare-floss`, `ssdeep`, `pytlsh`) install best-effort in Docker; if missing, that engine reports `unavailable` / `skipped` and the rest still run.

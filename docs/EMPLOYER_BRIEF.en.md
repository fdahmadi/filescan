# FileScan — Full Employer Briefing Guide

This document is the English version of the stakeholder briefing:

- **Part 1:** What the system is, where it starts, and how a scan runs
- **Part 2:** Plain-language explanations of each engine and helper feature, with simple examples

Persian twin: [EMPLOYER_BRIEF.fa.md](EMPLOYER_BRIEF.fa.md)  
More technical detail:  
[OVERVIEW.en.md](OVERVIEW.en.md) · [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md) · [ARCHITECTURE.en.md](ARCHITECTURE.en.md) · [CORE_DETECTION.en.md](CORE_DETECTION.en.md) · [STATUS.en.md](STATUS.en.md)

---

# Part 1 — System overview and execution flow

## 1) What is FileScan?

FileScan is a **multi-engine malware scanning API** for research / organizational pilots.

A user (or another system) uploads a file. Several security engines — each from its own angle — inspect it. At the end, the system returns one unified report with a final `verdict`:

| Verdict | Plain meaning |
|---------|----------------|
| `clean` | Reliable engines found nothing concerning |
| `suspicious` | There are warning signs, but not a hard malware call |
| `malicious` | Strong evidence of malware |
| `error` | No meaningful scan completed (for example all engines were down) |

### Three key sentences for employers

1. The system is an **orchestration layer**, not a single scanner; each engine can be enabled, disabled, or replaced.
2. The free detection core is **local**; cloud intel (abuse.ch / YARAify) uses **hash lookup only** — **file bytes are never uploaded**.
3. The output is one JSON report with a `verdict` and per-engine details — suitable for demos, pilots, and later integration into enterprise systems.

### What is ready today?

| Item | Status |
|------|--------|
| Free detection core + pilot API + demo UI | Ready |
| Local engines (ClamAV, YARA, precheck, oletools, LMD, CAPA, FLOSS, pefile) | Ready |
| Optional abuse.ch / YARAify lookup (hash only) | Ready |
| Sensitivity modes `lenient` / `balanced` / `strict` | Ready |
| Nested archives, cache, allow/deny lists, fuzzy matching | Ready |
| Redis queues, Grafana, paid commercial AV | Intentionally later |

---

## 2) Where does it start? Simple architecture

### Two main services (Docker Compose)

The pilot needs only **two** Compose services:

| Service | Port | Role |
|---------|------|------|
| **api** | `8001` | FastAPI + Orchestrator + almost all engines inside this container |
| **clamav** | `3310` | Official `clamd` antivirus daemon + signature database |

Other engines (YARA, precheck, oletools, LMD, CAPA, FLOSS, pefile) are **not** separate services; they run inside `api`.  
abuse.ch and YARAify are also not Compose services; when an Auth-Key is set, they perform **hash lookups** over the internet.

```text
[Client / browser / curl]
        │  HTTP on port 8001
        ▼
   [api service]
        │
        ├── In-process engines (YARA, precheck, oletools, …)
        ├── Subprocess for LMD / CAPA / FLOSS (when installed)
        ├── HTTPS hash-only → abuse.ch / YARAify (optional)
        │
        └── TCP 127.0.0.1:3310 ──► [clamav / clamd service]
```

### Entry points for users / employers

| URL / path | Purpose |
|------------|---------|
| `http://127.0.0.1:8001/ui/` | Demo UI for stakeholder walkthroughs |
| `POST /v1/scan` | Upload a file and receive scan results |
| `GET /v1/scan/{id}` | Fetch a stored result by scan ID |
| `GET /v1/health` | Service health and per-engine status |
| `http://127.0.0.1:8001/docs` | Swagger / interactive API docs |

Pilot security:

- `X-API-Key` header (demo default: `dev-demo-key`)
- Request rate limiting

### Code path (technical, but useful for understanding flow)

```text
Client / UI
  → app/main.py                 (FastAPI + UI mount)
  → app/api/routes.py           (/v1/* endpoints)
  → app/api/security.py         (API Key + rate limit)
  → app/services/orchestrator.py
  → app/engines/*               (each engine)
  → app/services/verdict.py     (final aggregation)
  → JSON persisted under results_dir
```

---

## 3) Exact scan execution order

Main endpoint: `POST /v1/scan` with a file (`multipart/form-data`) and optional fields:

- `sensitivity` = `lenient` | `balanced` | `strict` (default: `balanced`)
- `use_remote_intel` = `true` | `false` (default: `true` — only affects hash lookups)

### Step by step

```text
1) Receive file from client
   • Filename is required
   • Empty files are rejected
   • Default size cap is about 32 MB
   • API Key + rate limit checks

2) Write a temp file + MIME policy
   • If the type is denylisted (or outside allowlist), scanning stops

3) Orchestrator starts
   • Creates a scan UUID
   • Keeps a durable copy under upload_dir
   • Computes SHA256 (exact fingerprint)
   • If enabled: ssdeep / tlsh (approximate fingerprints)
   • Detects MIME type

4) Fast shortcuts (before heavy engines)
   • denylist (hash blacklist)  → immediate malicious and stop
   • allowlist (hash whitelist) → immediate clean and stop
   • cache (previous result for same hash + sensitivity) → return cached result
   • fuzzy (approximate similarity to prior samples)
       very high similarity can short-circuit like denylist

5) Content / signature / behavior engines — serial order:
     1. precheck
     2. ClamAV
     3. YARA
     4. oletools
     5. LMD
     6. CAPA
     7. FLOSS
     8. pefile
     9. abuse.ch     (if use_remote_intel=false → skipped)
    10. YARAify      (if use_remote_intel=false → skipped)

6) If the file is ZIP or TAR
   • Controlled extraction (nested depth limit, member count/size caps)
   • Warn on dangerous paths (for example ../../)
   • Re-scan each member with local content engines
     (precheck, ClamAV, YARA, oletools, LMD, CAPA, FLOSS, pefile)
   • Remote engines currently run on the outer file only

7) Aggregate verdict using sensitivity
8) Persist JSON result + return to client
9) Clean up the initial temporary upload
```

### Why this order matters

- **precheck** is fast and cheap; it raises early policy flags.
- **ClamAV / YARA / oletools / LMD** provide stronger (hard) evidence.
- **CAPA / FLOSS / pefile** help with new/unsigned samples but are noisier (soft).
- **abuse.ch / YARAify** come last because they are network hash lookups, not local content analysis order dependencies.

### Approximate report shape

For each scan the system returns something like:

- Scan ID, status, final verdict, sensitivity
- File info: name, size, SHA256, MIME
- Engine list: each `clean` / `suspicious` / `infected` / `matched` / `skipped` / …
- When present: threat names, details, per-engine duration

---

## 4) How the final verdict is built

Engines fall into two conceptual buckets:

| Signal type | Engines | Meaning for employers |
|-------------|---------|------------------------|
| **Hard** | ClamAV, YARA, LMD, oletools, abuse.ch, YARAify, hashlist, fuzzy | Stronger evidence; usually escalates quickly to `malicious` |
| **Soft** | precheck, CAPA, FLOSS, pefile, archive | Warnings / hints; weight depends on sensitivity |

### Sensitivity modes

| Mode | Plain behavior | Best when |
|------|----------------|-----------|
| `lenient` | Soft signals alone usually do not become `malicious` | You want fewer alarms |
| `balanced` | Default; balance coverage vs noise | Demos and everyday pilot use |
| `strict` | Even softer suspicious hits escalate faster to `malicious` | Priority is “do not miss threats” |

**Employer note:** A file can look clean to ClamAV while precheck or CAPA marks it suspicious. That disagreement is not a bug — it is the value of multi-engine scanning.

---

# Part 2 — Engines and helpers in plain language

Think of several security inspectors around one table. Each has a specialty. None of them sees every threat alone; the combined vote is stronger.

---

## 5) Quick table of all engines

| # | Engine | One line for employers | Signal |
|---|--------|------------------------|--------|
| 1 | **precheck** | Early checks: dangerous extensions, fake names, suspicious packing/encryption | Soft |
| 2 | **ClamAV** | Classic antivirus with a known-virus signature database | Hard |
| 3 | **YARA** | Customizable rules/patterns (text/behavioral fingerprints) | Hard |
| 4 | **oletools** | Inspect Office documents for dangerous macros | Hard |
| 5 | **LMD** | Focus on Linux/web malware (for example infected PHP) | Hard |
| 6 | **CAPA** | “What capabilities does this program have?” even without a known virus name | Soft |
| 7 | **FLOSS** | Recover hidden strings and addresses inside the file | Soft |
| 8 | **pefile** | Inspect Windows EXE/DLL structure | Soft |
| 9 | **abuse.ch** | “Has this hash been seen in a public malware corpus?” | Hard |
| 10 | **YARAify** | “Has the community recorded a rule/match for this hash?” | Hard |

---

## 6) Detailed engine explanations

### 6.1) Precheck — early “does this feel suspicious?” filter

**Role:** The first fast filter before heavy engines. Like a lobby guard who has not checked the ID with the central bank yet, but notices odd clothing or a strange name.

**What it checks**

- Is the file empty?
- Dangerous extension? (`.exe`, `.ps1`, `.bat`, `.vbs`, `.js`, …)
- **Fake / double extension names:** for example `invoice.pdf.exe` or `photo.png.exe` — looks like a document/image, but is executable
- **Name vs content mismatch:** `.jpg` / `.pdf` extension, but the bytes are really an executable (PE/ELF)
- **High entropy:** very random/compressed/encrypted-looking content — often packing or obfuscation
- Whether the file is an archive (for later stages)

**Easy examples**

- A file named `invoice.pdf.exe` → suspicious
- A `.png` that is actually an `.exe` → suspicious
- Unusually scrambled/packed content → high-entropy flag

**Important limitation**  
Precheck usually does **not** say “this is 100% malware” by itself. It is a **soft** signal; it helps other engines and is weighted by `sensitivity`.

**Why employers care**  
Many social-engineering attacks start with fake names and “harmless-looking” files; precheck covers that layer.

---

### 6.2) ClamAV — classic antivirus

**Role:** What most people mean by “antivirus”: a large database of known malware signatures.

**How it works (simple but accurate)**

- ClamAV runs as a separate always-on service (`clamd`) that keeps signatures in memory.
- The API streams the file to it over the internal network (TCP) and reads the reply.
- We do **not** spawn one-shot `clamscan` per file; this is the production-style approach.

**Typical outcomes**

- Signature hit → `infected` + threat name (for example `Eicar-Test-Signature`)
- No hit → `clean` from this engine’s point of view
- Service down → `error` / unhealthy on `/v1/health`

**Example**  
The standard EICAR test file is usually caught by both ClamAV and YARA → final verdict `malicious`.

**Signal type:** Hard — very reliable for known threats.  
**Caveat:** Brand-new malware (zero-day) may not be in the database yet; that is why other engines exist.

---

### 6.3) YARA — custom rules and patterns

**Role:** Instead of only “known virus name,” it looks for **patterns**: text fragments, specific bytes, combinations of indicators.

Like a detective saying: “If these three signs appear together, treat it as suspicious/malware” — even if antivirus has no name for it yet.

**What it covers**

- First-party project rules (for example EICAR test, suspicious script patterns)
- Community rules kept under `rules/yara/`
- Examples: PHP webshells, suspicious PowerShell, macro patterns, known malware strings

**Outcomes**

- Hard hits (for example malware tag / high severity) → usually push toward `malicious`
- Softer hits → `suspicious`

**Signal type:** Hard.  
**Employer advantage:** Rules can be customized for your environment (organization-specific patterns).

---

### 6.4) Oletools — Office documents and macros

**Role:** Specialist inspector for Word / Excel / Office files.

Many enterprise attacks start with email and a `.doc` / `.xls` attachment. The document looks normal; inside it is a malicious macro or script.

**What it asks**

- Does it contain macros?
- Do those macros do dangerous things? (run system commands, download files, talk to the network, …)

**Example**  
A “payroll.doc” that runs a script as soon as it is opened, without the user noticing.

**Signal type:** Hard.  
**Note:** For non-Office files it usually has little to say (and may skip).

---

### 6.5) LMD (Linux Malware Detect) — Linux and web malware

**Role:** Focus on servers and the web — areas where classic desktop antivirus is not always the best coverage.

**Typical targets**

- Infected PHP files on hosting
- Webshells / backdoors
- Linux-specific malware

**Example**  
A `shell.php` uploaded by an attacker so they can run commands later.

**Signal type:** Hard.  
**Practical note:** If the LMD binary is not installed, this engine becomes `skipped`/`unavailable` and the rest of the system still works. It is not a fragile hard dependency.

---

### 6.6) CAPA — “What can this program do?”

**Role:** Instead of asking “what is your virus name?”, it asks “what capabilities do you have?”

This matters a lot for **new** malware: it may be missing from every signature database, but its behavior still shows up.

**Example capabilities**

- Keylogging
- Covert network / command-and-control communication
- File encryption
- Persistence on the system
- Changing sensitive Windows settings

**Example**  
An unknown `.exe` that ClamAV does not recognize, but CAPA reports network + stealth capabilities → suspicious.

**Signal type:** Soft.  
**Why soft?** Some legitimate programs also have strong capabilities (for example IT tools). CAPA results are read cautiously and together with other engines.

---

### 6.7) FLOSS — recovering hidden strings

**Role:** Many malware samples scramble or encrypt important text so it is not obvious at first glance: server addresses, commands, keys, file paths.

FLOSS tries to **extract and reveal** those strings.

**Easy examples**

- Finding a suspicious command-and-control domain
- Finding hidden PowerShell commands inside a binary
- Strings that suggest ransomware or data theft tooling

**Signal type:** Soft.  
**Employer value:** Even without a virus name, textual clues are highly useful for human analysts or follow-up YARA rules.

---

### 6.8) Pefile — Windows executable structure (EXE/DLL)

**Role:** Looks at the “building structure” of a Windows executable, not the textual story of the content.

Like inspecting a building’s skeleton: the facade may look normal while the frame is abnormal.

**What it looks for**

- Extra data stuck at the end of the file (overlay) — sometimes used to hide a payload
- Sections that are both writable and executable (W+X) — a suspicious pattern in some packers
- Anomalies in resources / PE structure

**Example**  
An EXE whose structure looks like suspiciously packed malware, even with no virus signature.

**Signal type:** Soft.  
**Limitation:** On non-Windows files (for example a pure PDF or a real image) it usually does nothing or skips.

---

### 6.9) Abuse.ch (MalwareBazaar) — “Has this been seen before?”

**Role:** Query a large public malware sample corpus.

**Critical privacy point**  
Only the **SHA256** fingerprint is sent. **File contents are not uploaded.**  
For employers, the key sentence is: “Confidential organizational files do not leave the network; we only ask whether this fingerprint was previously recorded as malware.”

**Example**  
The same hash was previously listed in MalwareBazaar as a trojan → almost certainly `malicious`.

**Signal type:** Hard.  
**Optional:** Needs a free Auth-Key from https://auth.abuse.ch/  
Without a key, local engines still work; only this lookup is unavailable.

**Per-scan control:** With `use_remote_intel=false`, a scan can be fully local-only.

---

### 6.10) YARAify — community rules for the same hash

**Role:** Companion to abuse.ch. Asks whether the security community has recorded a YARA rule or related detection for this hash.

**Same as abuse.ch**

- Hash only
- No file upload
- Optional / needs a key (usually the same abuse.ch Auth-Key)

**Conceptual difference**

- abuse.ch is more “is this sample in the malware corpus?”
- YARAify is more “is there a community rule/match for this hash?”

**Signal type:** Hard.

---

## 7) Helper features (not content engines, but important)

### 7.1) Allowlist / Denylist (organizational white/black lists)

| List | Meaning |
|------|---------|
| **Denylist** | This hash is already known-bad → immediate `malicious` without a full scan |
| **Allowlist** | This hash is trusted by the organization (for example an internal installer) → immediate `clean` |

**Employer benefit:** Apply organizational policy without changing engines.

### 7.2) Cache (result cache)

If the same file (same SHA256) was scanned before with the same sensitivity settings, the previous result is returned.

**Benefit:** Faster repeats, less load on engines.

### 7.3) Fuzzy matching (approximate similarity)

Sometimes an attacker changes only a few bytes so the exact hash changes.  
Fuzzy matching (ssdeep / tlsh) says: “This file is very similar to a previously bad sample.”

- Very high similarity → can act like denylist
- Medium similarity → suspicious

### 7.4) Archive scanner (scan inside compressed files)

Malware is often hidden inside ZIP archives.

The system:

- Opens ZIP/TAR with safety limits (nested depth, total size, member count)
- Warns on dangerous paths such as `../../`
- Re-scans inner members with local content engines

**Note:** Remote lookups (abuse.ch / YARAify) are currently not repeated for archive members; they run on the outer file.

---

## 8) Why multiple engines? (threat → coverage)

| Real-world scenario | Which engine(s) help? |
|---------------------|------------------------|
| Known virus / EICAR test sample | ClamAV, YARA, sometimes abuse.ch |
| Office document with malicious macro | oletools (+ sometimes YARA) |
| Fake name (`photo.jpg.exe`) | precheck |
| Fake image/PDF that is really an EXE | precheck |
| Brand-new malware with no signature | CAPA, FLOSS, YARA, pefile |
| Infected PHP on a web server | LMD, YARA |
| Sample previously seen on the internet | abuse.ch, YARAify |
| Malware inside nested ZIP | archive + local engines on members |
| Slightly modified variant of prior malware | fuzzy |
| Official organizational installer | allowlist |

**Employer takeaway:**  
No single engine covers everything. Combining **hard** engines (confidence) and **soft** engines (new-sample coverage) with tunable sensitivity is the core logic of FileScan.

---

## 9) Design principles that matter to employers

| Principle | Plain meaning |
|-----------|----------------|
| **Pluggable** | New engine = add an adapter; the overall API stays stable |
| **Local-first** | The pilot works without paid cloud services |
| **Privacy-aware** | Only hashes go to abuse.ch / YARAify, never file bytes |
| **Never execute** | Uploads are not run; scanning is static only |
| **Sync MVP** | Scans are synchronous today; async Redis queues are a later phase |

---

## 10) Run for demo / presentation

```bash
cp -n .env.example .env
# Optional: set FILESCAN_ABUSECH_AUTH_KEY from https://auth.abuse.ch/
docker compose up --build -d
```

After startup:

| Item | Value |
|------|--------|
| Demo UI | http://127.0.0.1:8001/ui/ |
| Health | http://127.0.0.1:8001/v1/health |
| Swagger | http://127.0.0.1:8001/docs |
| Pilot API key | `dev-demo-key` |

**Note:** The first ClamAV start may take a few minutes while signatures download. The API waits until ClamAV is healthy.

Example scan from the command line:

```bash
curl -sS -H "X-API-Key: dev-demo-key" \
  -F "file=@./testdata/corpus/eicar.txt" \
  -F "sensitivity=balanced" \
  http://127.0.0.1:8001/v1/scan
```

Demo details: [DEMO.en.md](DEMO.en.md) · Test samples: [TEST_SAMPLES.en.md](TEST_SAMPLES.en.md) · Project status: [STATUS.en.md](STATUS.en.md)

---

## 11) One-page closing summary for a presentation

1. **FileScan** accepts a file and runs several independent security inspectors on it.  
2. **Entry:** API or demo UI on port `8001`; behind the scenes the Orchestrator manages order.  
3. **Hard engines** (ClamAV, YARA, oletools, LMD, hash intel) provide confidence.  
4. **Soft engines** (precheck, CAPA, FLOSS, pefile) improve coverage of new samples and name/structure tricks.  
5. **Sensitivity** controls how strict the organization wants to be.  
6. **Privacy:** remote intel sends hashes only.  
7. The output is one **unified report** that is clear for employer demos and ready for later enterprise integration.

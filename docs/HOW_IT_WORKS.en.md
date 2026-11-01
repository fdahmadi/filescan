# FileScan — What was built and how it runs

This document explains the current implementation in detail: what processes run, how a scan flows, and especially **how ClamAV is used** (not as a Python library).

---

## 1) One-line summary

A Python API (FastAPI) accepts a file, sends it to several **scan engines**, aggregates results, and returns a `verdict`.

| Engine | Connection method | Python library? |
|--------|-------------------|-----------------|
| **precheck** | In-process heuristics (entropy, extensions, MIME / disguise) | Our code |
| **pefile** | In-process PE structure heuristics (overlay, W+X, resources) | **Yes** — `pefile` |
| **ClamAV** | TCP socket to a separate `clamd` service (`INSTREAM` protocol) | **No** — only the stdlib `socket` module |
| **YARA** | In-process library inside the API | **Yes** — `yara-python` (`import yara`) |
| **oletools** | In-process Office macro analysis | **Yes** — `oletools` |
| **lmd** | Subprocess to `maldet` (Linux Malware Detect) | External binary (optional) |
| **capa** | Subprocess to Mandiant `capa -j` | External binary / `flare-capa` (optional) |
| **floss** | Subprocess to Mandiant `floss -j` | External binary / `flare-floss` (optional) |
| **abusech** | HTTPS hash lookup on MalwareBazaar | `httpx` + Auth-Key from https://auth.abuse.ch/ (no file upload) |
| **yaraify** | HTTPS hash lookup on YARAify | same key; UI https://yaraify.abuse.ch/ · API yaraify-api.abuse.ch |
| **archive** | Controlled ZIP/TAR extract (nested up to max_depth) + re-scan members with precheck / ClamAV / YARA / oletools / LMD / CAPA / FLOSS / pefile (not remote hash engines) | stdlib `zipfile` / `tarfile` |
| **hashlist / cache / fuzzy** | Allow/deny SHA256, result cache, ssdeep/tlsh similarity | JSON files + optional fuzzy libs |

`GET /v1/health` also returns `clamav_version` and `clamav_sigs_age_hint` when clamd is up.  
Scan responses may include `sensitivity`, `cache_hit`, `list_hit`, and `file.ssdeep` / `file.tlsh` when fuzzy libs are installed.  
Demo UI: `/ui` · status snapshot: [STATUS.en.md](STATUS.en.md) · tools: [TOOLS.en.md](TOOLS.en.md)

---

## 2) What was built?

### Docs
- Index: `docs/README.md` · status: `docs/STATUS.en.md` · demo: `docs/DEMO.en.md`
- This file — runtime details and ClamAV

### API code (simplified)
```
app/
  main.py                 # FastAPI + /ui static mount
  api/routes.py           # /v1/* (+ sensitivity form field)
  api/security.py         # X-API-Key + rate limit
  services/orchestrator.py
  services/verdict.py     # lenient / balanced / strict
  engines/*               # clamav, yara, oletools, lmd, capa, floss, abusech, yaraify, …
  static/ui/              # demo UI
```

### Rules and runtime
- `rules/yara/` — first-party + `community/`
- `docker-compose.yml` — `api` + `clamav`
- `scripts/smoke_scan.sh`, `scripts/benchmark_corpus.py`
- `tests/` — pytest suite

---

## 3) What runs at startup?

### Mode A — Docker Compose (full stack, recommended)

```bash
docker compose up --build
```

Exactly **two** Compose services (nothing else is required for the pilot):

| Service | Image / build | Port | Role |
|---------|---------------|------|------|
| `clamav` | `clamav/clamav:1.4` | `3310` | Antivirus daemon `clamd` + signature DB |
| `api` | Built from `Dockerfile` | `8001` | FastAPI + all other local engines in-process |

Other scanners are **not** separate containers: YARA / precheck / oletools / LMD / CAPA / FLOSS / pefile run **inside** the `api` image. Remote hash lookups (abuse.ch, YARAify) need no Compose service.

Default Compose uses **host networking** (API → ClamAV at `127.0.0.1:3310`):

```
[Your client]
      │  HTTP :8001
      ▼
[api process]  ──TCP 127.0.0.1:3310──►  [clamd]
   │
   └── YARA / LMD / CAPA / FLOSS / oletools in the same container (no extra services)
```

Important compose env vars for API:

- `FILESCAN_CLAMAV_HOST=127.0.0.1`
- `FILESCAN_CLAMAV_PORT=3310`
- `FILESCAN_YARA_RULES_DIR=/app/rules/yara`
- `FILESCAN_CAPA_RULES_DIR=/opt/capa-rules`

**Note:** On first start, ClamAV may take several minutes to download signatures via `freshclam`. The API waits until ClamAV is healthy (`depends_on`) — that is a startup order rule, not a third service.

### Mode B — Local API without Docker ClamAV

You can run only Python and disable ClamAV:

```bash
source .venv/bin/activate
FILESCAN_CLAMAV_ENABLED=false \
FILESCAN_YARA_RULES_DIR=./rules/yara \
PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In this mode:

- YARA works
- ClamAV returns `skipped` (no `clamd` / disabled)

If you install ClamAV locally and `clamd` listens on `127.0.0.1:3310`:

```bash
FILESCAN_CLAMAV_ENABLED=true \
FILESCAN_CLAMAV_HOST=127.0.0.1 \
FILESCAN_CLAMAV_PORT=3310 \
...
```

---

## 4) Exact flow of one scan request

Endpoint: `POST /v1/scan` (`multipart/form-data`: `file`, optional `sensitivity`, `use_remote_intel`)

Code path: `app/api/routes.py` → `ScanOrchestrator.scan_file` → engines → `aggregate_verdict`

**Full ordered pipeline (shortcuts, engine list, archive members):**  
→ [SCAN_PIPELINE.en.md](SCAN_PIPELINE.en.md)

Summary:

```
1) Access checks + read upload (empty / oversize → error)
2) Temp file + MIME policy (disallowed → HTTP 415)
3) Orchestrator: UUID, durable copy, SHA256, optional ssdeep/tlsh, MIME
4) Fast shortcuts (first hit stops):
     denylist → malicious | allowlist → clean | cache hit | high-confidence fuzzy
5) Serial engines: precheck → clamav → yara → oletools → lmd →
                   capa → floss → pefile → abusech → yaraify
   (remote hash engines skipped when use_remote_intel=false)
6) If ZIP/TAR: controlled extract + re-scan members with local content engines
7) aggregate_verdict(sensitivity) → persist JSON → return
8) routes.py deletes the temp upload
```

Other endpoints:

| Method | Path | Role |
|--------|------|------|
| `GET` | `/v1/health` | Engine healthchecks + ClamAV version hint |
| `GET` | `/v1/scan/{id}` | Read stored result from disk |
| UI | `/docs` · `/ui` | Swagger · demo UI |

### Verdict logic (current)

Implementation: `app/services/verdict.py` (also exposed via `ScanOrchestrator.aggregate_verdict`).

Hard engines (e.g. ClamAV, YARA, oletools, LMD, hash intel, fuzzy) vs soft engines (precheck, CAPA, FLOSS, pefile, archive) are weighted by `sensitivity`. Details: [CORE_DETECTION.en.md](CORE_DETECTION.en.md).

---

## 5) ClamAV — exactly how it is used

### Short answer

**We do not use a Python library such as `pyclamd`.**  
**We also do not subprocess `clamscan`.**  

Instead we open a **TCP socket** to the official ClamAV daemon **`clamd`** and speak its native protocol.

This is the usual production approach: one always-on `clamd` keeps signatures in memory; clients stream file bytes to it.

### ClamAV components (conceptual)

| Component | Role |
|-----------|------|
| `clamd` | Scanner daemon; listens on port 3310 (our Docker setup) |
| Signature database | Typically `/var/lib/clamav` inside the container |
| `freshclam` | Updates signatures (handled inside the official image) |
| `clamscan` | One-shot CLI tool — **we do not use it** |

The `clamav/clamav:1.4` container runs `clamd`.

### Our code

`app/engines/clamav.py` → class `ClamAVEngine`

Settings from `app/config.py`:

| Env var | Default | Meaning |
|---------|---------|---------|
| `FILESCAN_CLAMAV_ENABLED` | `true` | Enable/disable engine |
| `FILESCAN_CLAMAV_HOST` | `clamav` | TCP host (Docker service name) |
| `FILESCAN_CLAMAV_PORT` | `3310` | clamd port |
| `FILESCAN_CLAMAV_TIMEOUT_SECONDS` | `60` | Socket timeout |

### What the protocol does

#### Healthcheck (`GET /v1/health`)

1. TCP connect to `host:port`
2. Send: `PING\0`
3. Expect: `PONG`
4. If connect fails → unhealthy

#### File scan (`INSTREAM`)

ClamAV supports several methods (`SCAN` for a local path, `INSTREAM` to send content over the socket, …).

We use **`INSTREAM`** because:

- API and ClamAV may run in **two separate containers**
- A path inside the API container is not visible to `clamd`
- With INSTREAM, **file bytes are sent over the network** and clamd scans those bytes

Steps in `_instream`:

```
1) TCP connect to clamav:3310
2) Send command:  zINSTREAM\0
   (z prefix = null-terminated reply)
3) Loop:
     read 2048 bytes from file
     send 4-byte big-endian chunk length (struct ">I")
     send the chunk
4) Send length 0  → end of stream
5) Read textual reply from clamd
```

Example clamd replies:

| Approx. reply | Meaning in our code |
|---------------|---------------------|
| `stream: OK` | Clean → `status=clean` |
| `stream: Eicar-Test-Signature FOUND` | Infected → `status=infected` + threat name |
| Text containing `ERROR` | Error → `status=error` |

Parser: `_parse_reply`.

### Why not a library?

Packages like `pyclamd` exist; they ultimately speak the same socket protocol.

Why we implemented raw `socket`:

- Fewer dependencies
- Full control over timeouts and errors
- Transparent for a research project (exact request/response is visible)
- No need to install `clamscan` inside the API container

### Option comparison

| Approach | Used here? | Notes |
|----------|------------|-------|
| Socket to `clamd` + INSTREAM | **Yes (current)** | Best for multi-service Docker |
| `pyclamd` library | No | Same protocol under the hood |
| `subprocess` → `clamscan file` | No | New process each time; slower |
| Link libclamav into Python | No | Complex and unnecessary |

### ClamAV scan diagram

```
[FastAPI / ClamAVEngine]
        │
        │  TCP  clamav:3310
        │  zINSTREAM + file chunks
        ▼
[clamd in clamav container]
        │
        │  compare against virus database
        ▼
   "stream: OK"  or  "stream: Name FOUND"
        │
        ▼
[ClamAVEngine._parse_reply] → EngineResult
```

---

## 6) YARA — for contrast (this one is a library)

Code: `app/engines/yara_engine.py`

- Package: `yara-python` in `requirements.txt`
- In code: `import yara`
- On Orchestrator startup, all `.yar` / `.yara` files under the rules dir are compiled
- Per scan: `rules.match(path)`
- No separate service; everything runs inside the API process

Current rules:

- `rules/yara/eicar.yar` — EICAR test string
- `rules/yara/suspicious_scripts.yar` — PowerShell / PHP webshell / macro patterns

If a rule has tags like `malware` or `severity=high` → `matched` → overall `malicious`  
Softer hits → `suspicious`

---

## 7) What the Orchestrator does

Code: `app/services/orchestrator.py`

- Owns the full scan pipeline: identity → hash lists → cache → fuzzy → engines → archive → verdict  
  Step-by-step: [SCAN_PIPELINE.en.md](SCAN_PIPELINE.en.md)
- Loads engines from `build_engines()` (precheck, ClamAV, YARA, oletools, LMD, CAPA, FLOSS, pefile, abuse.ch, YARAify)
- Every engine shares: `scan(path) -> EngineResult` and `healthcheck()`
- Later VirusTotal / commercial AV = new class, same interface; API unchanged

Engine factory: `app/engines/__init__.py` → `build_engines()`

---

## 8) Important settings (env)

Prefix: `FILESCAN_`

See `.env.example` at repo root.

```text
FILESCAN_CLAMAV_ENABLED=true
FILESCAN_CLAMAV_HOST=clamav          # in Docker
# FILESCAN_CLAMAV_HOST=127.0.0.1     # if local clamd
FILESCAN_CLAMAV_PORT=3310

FILESCAN_YARA_ENABLED=true
FILESCAN_YARA_RULES_DIR=/app/rules/yara   # or local ./rules/yara

FILESCAN_MAX_UPLOAD_BYTES=33554432
FILESCAN_UPLOAD_DIR=/tmp/filescan/uploads
FILESCAN_RESULTS_DIR=/tmp/filescan/results
```

---

## 9) Manual testing

```bash
# health
curl -s http://127.0.0.1:8000/v1/health | jq

# scan a file
curl -s -F "file=@./myfile.bin" http://127.0.0.1:8000/v1/scan | jq

# ready script (EICAR)
./scripts/smoke_scan.sh
```

With healthy ClamAV, an EICAR file is usually detected by both ClamAV (`Eicar-Test-Signature`) and YARA (`eicar_test_file`), so `verdict` is `malicious`.

---

## 10) Current status

See [STATUS.en.md](STATUS.en.md). Practical notes:

- Pilot Compose: API on **8001**, host networking (see [DEPLOY.en.md](DEPLOY.en.md))
- Local API can run with YARA only (`FILESCAN_CLAMAV_ENABLED=false`)
- If Debian apt fails during image build: `docker build --network=host`

---

## 11) Ultra-short recap

1. **Python API** accepts the file and calls the Orchestrator.  
2. **YARA** = in-process library (`yara-python`).  
3. **ClamAV** = separate service (`clamd`); we wrote a **TCP INSTREAM client** — not a library, not `clamscan`.  
4. Engine results return as one JSON with a `verdict`.  
5. Optional engines (LMD / CAPA / FLOSS / abuse.ch) follow the same adapter pattern; ExifTool / Loki / extra Clam feeds are deferred on purpose (see [NEXT_PATHS.en.md](NEXT_PATHS.en.md)).

Related: [SCAN_PIPELINE.en.md](SCAN_PIPELINE.en.md) · [STATUS.en.md](STATUS.en.md) · [OVERVIEW.en.md](OVERVIEW.en.md) · [ARCHITECTURE.en.md](ARCHITECTURE.en.md) · [ROADMAP.en.md](ROADMAP.en.md) · [DEMO.en.md](DEMO.en.md)

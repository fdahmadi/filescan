# FileScan — Architecture Overview

Research malware-scanning API: accept a file, scan with local (and optional remote hash) engines, return a unified report. Demo UI at `/ui` for stakeholders.

**Status:** [STATUS.en.md](STATUS.en.md)

## Goal

Build an **orchestrator API** that:

1. Accepts a file upload  
2. Runs free local scanners (and optional abuse.ch hash lookup)  
3. Aggregates results into one verdict (with sensitivity)  
4. Stays pluggable for cloud/commercial engines later  

## High-level design

```
Client (curl / Swagger / demo UI /ui)
  │  POST /v1/scan  (multipart + optional sensitivity)
  │  GET  /v1/scan/{id}
  │  GET  /v1/health
  ▼
API (FastAPI) — X-API-Key + rate limit on scan
  ▼
Orchestrator
  ├─ MIME policy, SHA256, cache, allow/deny, fuzzy
  ├─ precheck · clamav · yara · oletools · lmd · capa · floss · pefile
  ├─ archive extract + member re-scan (precheck + local content engines)
  ├─ abusech / yaraify (optional Auth-Key, outer-file hash only)
  └─ Aggregator (lenient | balanced | strict) → verdict
```

Compose for the pilot: **only** `api` + `clamav` (other engines live inside the API image).

## Core principles

| Principle | Meaning |
|-----------|---------|
| Pluggable engines | Same `ScanEngine` interface |
| Local-first | Pilot does not require paid APIs |
| Privacy-aware | No sample upload to abuse.ch; hash lookup only |
| Never execute samples | Scan only; do not run uploads |
| Sync MVP | Async Redis queue is a later phase |

## Verdict model

| Verdict | When (simplified) |
|---------|-------------------|
| `clean` | Actionable engines clean |
| `suspicious` | Soft / hard soft signals (depends on sensitivity) |
| `malicious` | Hard infected/matched, or strict escalation |
| `error` | No actionable engine results |

Details: [CORE_DETECTION.en.md](CORE_DETECTION.en.md)

## Response shape (conceptual)

```json
{
  "id": "uuid",
  "status": "completed",
  "verdict": "malicious",
  "sensitivity": "balanced",
  "file": {
    "name": "sample.exe",
    "size": 12345,
    "sha256": "...",
    "mime": "application/x-dosexec"
  },
  "engines": [
    {
      "name": "clamav",
      "status": "infected",
      "threats": ["Win.Trojan.Example"],
      "duration_ms": 120
    }
  ]
}
```

## Components

### API layer
- `POST /v1/scan` — sync scan (+ `sensitivity` form field)  
- `GET /v1/scan/{id}` — stored result  
- `GET /v1/health` — engines + ClamAV version hint  
- Static demo UI — `/ui`  
- Swagger — `/docs`  

### Engines
- **precheck**, **ClamAV**, **YARA**, **oletools**, **archive**, **lmd**, **capa**, **floss**, **pefile**  
- **abusech**, **yaraify** (optional)  
- **fuzzy** / **hashlist** (lists + similarity)  
- Later: VirusTotal, MetaDefender, commercial AV  

Catalog: [TOOLS.en.md](TOOLS.en.md)

### Rules
- `rules/yara/` first-party + `rules/yara/community/`  
- Python guards: MIME, archive depth/size, entropy  

## Security notes

- Upload size / MIME / archive limits  
- Quarantine uploads; prefer TTL cleanup (recommended next ops item)  
- Do not expose publicly without auth, rate limits, TLS  
- Change `dev-demo-key` before shared deploy  
- Keep ClamAV signatures updated (`freshclam`)  

## Technology choices (pilot)

- **Language:** Python 3.11+  
- **API:** FastAPI + Uvicorn  
- **Local engines:** ClamAV service + tools inside API image  
- **Packaging:** Docker Compose (`api` + `clamav`, host networking on this pilot)  
- **Queue (later):** Redis + workers  

Related: [OVERVIEW.en.md](OVERVIEW.en.md) · [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md) · [DEPLOY.en.md](DEPLOY.en.md) · [ROADMAP.en.md](ROADMAP.en.md)

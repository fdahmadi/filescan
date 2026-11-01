# FileScan — Scan pipeline (exact execution order)

This is the **code-accurate** order of checks for one `POST /v1/scan` request.  
Plain-language version for stakeholders: [EMPLOYER_BRIEF.en.md](EMPLOYER_BRIEF.en.md) §3.  
Runtime / ClamAV details: [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md).  
Verdict weighting: [CORE_DETECTION.en.md](CORE_DETECTION.en.md).

Primary code:

| Stage | File |
|-------|------|
| HTTP + MIME gate | `app/api/routes.py` |
| Orchestration | `app/services/orchestrator.py` → `ScanOrchestrator.scan_file` |
| Engine list / order | `app/engines/__init__.py` → `build_engines()` |
| Final verdict | `app/services/verdict.py` → `aggregate_verdict` |

---

## 1) Overview diagram

```text
Client
  │  multipart file + sensitivity + use_remote_intel
  ▼
routes.py
  │  API key / rate limit
  │  read bytes → size checks → temp file
  │  MIME allow/deny  ──reject──► HTTP 415
  ▼
orchestrator.scan_file
  │  copy to upload_dir, SHA256, optional fuzzy hashes, MIME
  │
  ├─ denylist hit  ──────────────────────────────► malicious (stop)
  ├─ allowlist hit ──────────────────────────────► clean (stop)
  ├─ cache hit     ──────────────────────────────► cached result (stop)
  ├─ fuzzy high-confidence hit ─────────────────► verdict + stop
  │
  ├─ engines (serial): precheck → clamav → yara → oletools →
  │                     lmd → capa → floss → pefile →
  │                     abusech / yaraify (or skipped)
  │
  ├─ if ZIP/TAR: archive extract + re-scan members
  │              with local content engines only
  │
  ▼
aggregate_verdict(sensitivity) → persist JSON → return ScanResult
  │
  ▼
routes.py finally: delete temp upload
```

Early exits exist on purpose: known hashes and cache should not burn CPU or remote quota.

---

## 2) Phase A — API gate (`routes.py`)

Runs **before** the orchestrator.

1. **Access** — `X-API-Key` (if configured) + per-key/IP rate limit  
   (`app/api/security.py`)
2. **Form parsing**
   - `sensitivity`: `lenient` | `balanced` | `strict` (default `balanced`)
   - `use_remote_intel`: `true` | `false` (default `true`)  
     When `false`, only hash-lookup engines that contact third parties are skipped.  
     File bytes are **never** uploaded to abuse.ch / YARAify either way.
3. **Upload validation**
   - Filename required
   - Empty body → 400
   - Size over `FILESCAN_MAX_UPLOAD_BYTES` (default ~32 MiB) → 413
4. **Temp file** — bytes written to a `NamedTemporaryFile` (suffix from original name)
5. **MIME policy** — `check_mime_policy(...)`  
   Allowlist / denylist from settings. Fail → **HTTP 415**, no scan.
6. **Hand-off** — `orchestrator.scan_file(tmp_path, filename, sensitivity, use_remote_intel)`
7. **Cleanup** — `finally: tmp_path.unlink(...)` after the orchestrator returns (or errors)

---

## 3) Phase B — Prepare identity (`orchestrator.scan_file`)

Always runs for an accepted upload:

1. Allocate `scan_id` (UUID)
2. Durable copy: `upload_dir / "{scan_id}_{original_name}"`
3. Compute **SHA256** (`sha256_file`)
4. If fuzzy hashing enabled: **ssdeep** and/or **tlsh**
5. Build `FileInfo` (name, size, sha256, mime, optional fuzzy hashes)

No verdict yet — this is fingerprinting only.

---

## 4) Phase C — Fast shortcuts (may stop the scan)

Checked **in this order**. First match that decides returns immediately (result is persisted).

### C1 — Hash denylist

`HashListStore.check(sha256)`

- Hit `"deny"` → `verdict=malicious`, single synthetic engine `hashlist`, **stop**

### C2 — Hash allowlist

- Hit `"allow"` → `verdict=clean`, engine `hashlist`, **stop**

Deny is checked before allow in the sense that the store returns one list outcome; a deny decision wins when the digest is on the denylist.

### C3 — Result cache

If `FILESCAN_CACHE_ENABLED` (or equivalent) is on:

- Lookup key: **SHA256 + sensitivity + use_remote_intel**
- Hit → return cached engines/verdict with a new `scan_id`, `cache_hit=True`, **stop**

### C4 — Fuzzy similarity (optional)

If fuzzy hash **and** fuzzy match are enabled:

- Compare ssdeep/tlsh against denylist / prior samples (`match_fuzzy`)
- No hit → continue (no fuzzy engine row, or none appended)
- Hit with **high** confidence → `EngineResult` named `fuzzy` with status `matched` (or `suspicious` if weaker)  
  High-confidence `infected`/`matched` **short-circuits** like denylist: verdict aggregated from that alone, cached if eligible, **stop**
- Weaker suspicious fuzzy hit still continues into full engines (result is kept in `engine_results`)

---

## 5) Phase D — Content / intel engines (serial)

Loop: `for engine in self.engines` from `build_engines(settings)`.

Exact construction order:

| # | Engine name | Role (short) |
|---|-------------|--------------|
| 1 | `precheck` | Cheap heuristics (entropy, name/MIME disguise, …) |
| 2 | `clamav` | Signature AV via `clamd` TCP `INSTREAM` |
| 3 | `yara` | In-process YARA rules |
| 4 | `oletools` | Office macro / OLE analysis |
| 5 | `lmd` | Linux Malware Detect (`maldet` subprocess) |
| 6 | `capa` | Capability extraction (`capa -j`) |
| 7 | `floss` | Obfuscated string recovery (`floss -j`) |
| 8 | `pefile` | PE structure heuristics |
| 9 | `abusech` | MalwareBazaar **hash** lookup (HTTPS) |
| 10 | `yaraify` | YARAify **hash** lookup (HTTPS) |

Rules in this phase:

- Engines run **one after another** (not parallel today).
- Disabled / unhealthy engines typically return `skipped` / `unavailable` / `error` from their own `scan()` — the loop still continues.
- If `use_remote_intel=false` and `engine.name` is in `REMOTE_ENGINE_NAMES` (`abusech`, `yaraify`):
  - No network call
  - Append `status=skipped` with detail `use_remote_intel=false`
  - Continue

There is **no** early stop between these engines based on an intermediate hit (unlike denylist / high fuzzy). All enabled engines in the list are attempted so the report stays multi-engine.

---

## 6) Phase E — Archive members (optional)

After the outer-file engine loop:

1. If archive scanning is disabled → skip
2. Controlled extract of ZIP/TAR into `{scan_id}_extract`  
   Caps: max members, total bytes, per-member bytes, nest depth  
   (`app/services/archive.py`)
3. If not an archive → no extra results
4. Else append a synthetic engine row named **`archive`**:
   - `clean` / `suspicious` (dangerous paths, warnings) / `error`
5. For **each extracted member**, re-run only **content** engines:

   `CONTENT_ENGINE_NAMES` =  
   `precheck`, `clamav`, `yara`, `oletools`, `lmd`, `capa`, `floss`, `pefile`

   - Remote hash engines (`abusech`, `yaraify`) are **not** re-run on members
   - Clean/skipped/unavailable member scans are omitted from the report noise filter
   - Interesting hits appear as `"{engine}@{relative/path}"` (e.g. `yara@payloads/evil.exe`)
6. Extract directory is always removed in `finally`

---

## 7) Phase F — Verdict, persist, cache write

1. `compute_verdict(engine_results, sensitivity)`  
   Soft vs hard engines and how `lenient` / `balanced` / `strict` change outcomes:  
   [CORE_DETECTION.en.md](CORE_DETECTION.en.md)
2. Build `ScanResult` (`status=completed`, `cache_hit=False`, timestamps, …)
3. Persist JSON: `results_dir / "{scan_id}.json"`
4. If cache enabled and verdict is not `error` / `unknown` → store for future C3 hits
5. Return to `routes.py` (temp upload deleted there)

Retrieve later: `GET /v1/scan/{scan_id}` → `orchestrator.get_result`.

---

## 8) Why this order?

| Choice | Reason |
|--------|--------|
| MIME before orchestrator | Reject disallowed types without hashing or engines |
| Deny / allow / cache before engines | Cheap exact decisions; save CPU and remote quota |
| Fuzzy before full engine loop | Near-duplicate of known-bad can short-circuit |
| `precheck` first among engines | Fast local heuristics |
| ClamAV / YARA / oletools / LMD mid-pack | Stronger (“hard”) evidence |
| CAPA / FLOSS / pefile after | Useful on novel samples; noisier (“soft”) |
| abuse.ch / YARAify last | Network hash intel; independent of local content order; easy to skip with `use_remote_intel=false` |
| Archive after outer engines | Outer file still fully scored; members add nested coverage |
| Content-only on members | Avoid remote lookups per zip entry; keep extract path local |

---

## 9) Short-circuit cheat sheet

| Condition | Final-ish outcome | Engines after? |
|-----------|-------------------|----------------|
| MIME denied | HTTP 415 | No |
| SHA256 denylist | `malicious` | No |
| SHA256 allowlist | `clean` | No |
| Cache hit | Prior verdict | No |
| High-confidence fuzzy | Aggregated from fuzzy | No |
| Soft fuzzy only | Continues | Yes |
| Any mid-loop engine hit | Continues (full report) | Remaining engines still run |
| Archive | Extra rows only | After outer engines |

---

## 10) Related docs

- [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md) — processes, ClamAV protocol, startup  
- [CORE_DETECTION.en.md](CORE_DETECTION.en.md) — sensitivity and hard/soft signals  
- [TOOLS.en.md](TOOLS.en.md) — engine / library catalog  
- [ARCHITECTURE.en.md](ARCHITECTURE.en.md) — system shape  
- [STATUS.en.md](STATUS.en.md) — what is done vs deferred  

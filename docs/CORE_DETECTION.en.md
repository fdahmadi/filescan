# FileScan — Detection core

How FileScan decides **clean / suspicious / malicious**.  
Pilot API/UI details: [NEXT_PATHS.en.md](NEXT_PATHS.en.md) · [DEMO.en.md](DEMO.en.md) · [STATUS.en.md](STATUS.en.md).

Grafana, Redis queues, and full product dashboards are **out of scope** here. A small demo UI at `/ui` exists for stakeholders.

---

## What exists today

| Piece | Status |
|-------|--------|
| ClamAV / YARA / precheck / archive / oletools | Done |
| `pefile` PE structure heuristics | Done |
| LMD / CAPA / FLOSS | Done (in API image when install succeeds) |
| MalwareBazaar (`abusech`) + YARAify | Done (optional Auth-Key) |
| First-party + curated community YARA | Done |
| SHA256 cache + allow/deny + fuzzy similarity | Done |
| Nested archives (`max_depth`, default 2); member re-scan includes `precheck` | Done |
| Sensitivity `lenient` / `balanced` / `strict` | Done |
| Corpus benchmark script | Done |

---

## Optional remote engines (free Auth-Key)

| Engine | API | Upload? |
|--------|-----|---------|
| `abusech` | MalwareBazaar `get_info` | Never |
| `yaraify` | YARAify `lookup_hash` | Never |

Local engines work without a key (`/v1/health` shows those two unhealthy until configured).

**Per-scan opt-out:** form field `use_remote_intel=true|false` on `POST /v1/scan` (default `true`).  
When `false`, `abusech` / `yaraify` are **skipped** (local-only). Even when `true`, only the **SHA256 hash** is queried — file bytes are never uploaded. The demo UI exposes the same choice as a checkbox.

### Domains

| URL | Purpose |
|-----|---------|
| https://auth.abuse.ch/ | **Create account / get Auth-Key** |
| https://bazaar.abuse.ch/ | MalwareBazaar UI |
| https://yaraify.abuse.ch/ | YARAify UI |
| https://mb-api.abuse.ch/api/v1 | MalwareBazaar API (default) |
| https://yaraify-api.abuse.ch/api/v1 | YARAify API (default) |

### Setup

1. https://auth.abuse.ch/ → Auth-Key  
2. `.env`: `FILESCAN_ABUSECH_AUTH_KEY=...` (YARAify reuses it unless `FILESCAN_YARAIFY_AUTH_KEY` is set)  
3. `docker compose up -d --force-recreate api`  
4. Health: `abusech` / `yaraify` healthy  

Only **hashes** are sent — no file upload to abuse.ch. Fair use applies.

---

## Verdict rules

**Hard engines:** ClamAV, YARA, LMD, oletools, abuse.ch, YARAify, hashlist, fuzzy  
**Soft engines:** precheck, CAPA, FLOSS, pefile, archive heuristics

| Signal | Typical verdict |
|--------|-----------------|
| Denylist / strong fuzzy / hard `infected`/`matched` | `malicious` |
| Soft hits | Depend on **sensitivity** |
| Allowlist / all clean | `clean` |

### Sensitivity

Form field on `POST /v1/scan` and select in `/ui`.

| Mode | Behavior |
|------|----------|
| `lenient` | Soft engines alone never become `malicious` |
| `balanced` | Default; soft `matched` → suspicious |
| `strict` | Soft/hard suspicious (and soft matched) escalate to `malicious` |

Cache keys include sensitivity.

Code: `app/services/verdict.py`

### Fuzzy denylist shape

```json
{
  "hashes": ["sha256..."],
  "ssdeep": ["3:abc..."],
  "tlsh": ["T1A2..."]
}
```

---

## Delivery order (historical)

```text
Steps 1–6   free detection polish                         ✅
Path A/A+   MIME + CAPA/LMD/FLOSS + YARA + sensitivity    ✅
Path B      API key + rate limit + Swagger + demo UI      ✅
── deferred: ExifTool, Loki/Paranoya, extra Clam feeds ──
── employer-pick candidates: DiE / Manalyze / PDF / binwalk (TOOLS §5c; precheck disguise + pefile done) ──
── evaluated/rejected as engine: Exploit-DB (TOOLS §5b) ──
── later: Redis async / Grafana / paid cloud ──
```

## Corpus + benchmark

Folder `testdata/corpus/` + `scripts/benchmark_corpus.py` — offline file → verdict table.  
Not a separate service. See [testdata/corpus/README.md](../testdata/corpus/README.md).

## Completing without abuse.ch

1. Sensitivity modes  
2. YARA + allow/deny + fuzzy  
3. Corpus benchmark after rule changes  

---

## Related

- [STATUS.en.md](STATUS.en.md) · [TOOLS.en.md](TOOLS.en.md) · [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md)  
- [DEPLOY.en.md](DEPLOY.en.md) · [DEMO.en.md](DEMO.en.md) · [ROADMAP.en.md](ROADMAP.en.md)

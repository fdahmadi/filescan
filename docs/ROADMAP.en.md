# FileScan — Roadmap

Phased plan focused on **free software we can install ourselves** (Docker or direct/apt), then optional cloud/paid tools only when needed.

### Where we are now

| Track | State |
|-------|--------|
| Detection core steps 1–6 | Done |
| Paths A / A+ / B (engines in Docker, API key, UI, sensitivity) | Done |
| Recommended next | Stakeholder demo, then ops (logging / TTL / real API keys) — [STATUS.en.md](STATUS.en.md) |
| Not building yet | Grafana / Redis productization / paid cloud unless required |

Details: [CORE_DETECTION.en.md](CORE_DETECTION.en.md) · [NEXT_PATHS.en.md](NEXT_PATHS.en.md) · [DEMO.en.md](DEMO.en.md)

Sections below keep the full long-term map; treat observability and paid cloud as later.

**Legend**

| Tag | Meaning |
|-----|---------|
| Free / self-host | No license fee; we install on our server |
| Docker | Prefer Compose service |
| Direct | apt/pip/binary on host or inside API image |
| Free API (quota) | Remote free tier; no install, but rate limits / fair use |
| Paid later | Employer budget only after free stack is measured |

---

## Phase 0 — Foundation (done)

**Stack already in repo (all free):**

| Component | Install | Status |
|-----------|---------|--------|
| FastAPI API | Direct (pip) / Docker image | Done |
| ClamAV (`clamd`) | Docker `clamav/clamav` or apt `clamav-daemon` | Done (Compose) |
| YARA | Direct `yara-python` + `.yar` files | Done |
| Orchestrator + verdict | Our code | Done |
| Health / scan endpoints | Our code | Done |

- [x] Architecture + roadmap docs (EN)
- [x] Pluggable `ScanEngine` interface
- [x] ClamAV TCP INSTREAM adapter
- [x] YARA adapter + sample rules
- [x] Docker Compose (`api` + `clamav`)
- [x] Deploy guide

**Outcome:** Working local multi-engine API with free tools only.

---

## Phase 1 — Harden the free MVP (self-hosted only)

No paid products. Everything below is free and installable by us.

### 1.1 Async jobs & queue

| Piece | Free option | How |
|-------|-------------|-----|
| Broker / job state | **Redis** | Docker: `redis:7-alpine` |
| Workers | Celery / RQ / ARQ | Direct pip inside `api` or separate `worker` service |
| Job API | Our code | `POST /v1/scan` → `202` + id; `GET /v1/scan/{id}` polls |

- [ ] Add `redis` service to `docker-compose.yml`
- [ ] Background worker container (same image, different command)
- [ ] Persist job status in Redis (+ optional JSON on disk)
- [ ] Keep sync mode as fallback for small files / tests

### 1.2 Storage & safety (free)

| Piece | Free option | How |
|-------|-------------|-----|
| Quarantine / uploads | Docker volume or host path | Already `/tmp/filescan`; harden with TTL |
| Object storage (optional) | **MinIO** | Docker `minio/minio` if multi-node later |
| MIME / type | **libmagic** (`python-magic`) | apt `libmagic1` (already in Dockerfile) |
| Archives | **libarchive** / Python `zipfile`+limits | Direct — depth/size/bomb guards |
| Hashing | SHA256 (stdlib) | Direct — done |

- [x] Upload size / MIME allowlist / archive-depth limits (Path A)
- [ ] Quarantine TTL cleanup job (cron in worker or simple loop)
- [ ] Optional MinIO only if volume alone is not enough

### 1.3 Auth, limits, observability (free)

| Piece | Free option | How |
|-------|-------------|-----|
| API key auth | Our code | Header `X-API-Key` |
| Rate limit | **SlowAPI** or Redis counters | Direct pip + Redis |
| Reverse proxy | **Nginx** or **Caddy** | Docker or apt |
| Metrics | **Prometheus** client + **Grafana** | Docker Compose add-ons |
| Logs | structured JSON → stdout | Docker logging driver |

- [x] API key + basic rate limiting (Path B pilot: `X-API-Key`)
- [x] MIME allowlist / denylist intake policy (Path A)
- [ ] Structured logging and scan duration metrics
- [ ] Optional `nginx` / `prometheus` / `grafana` Compose profiles

### 1.4 Detection quality (free rules & ClamAV)

| Piece | Free option | How |
|-------|-------------|-----|
| ClamAV DB update | `freshclam` (inside official image) | Docker volume `clamav_data` |
| Extra Clam signatures (optional) | Community / sanesecurity-style feeds | Mount into ClamAV (evaluate license/trust) |
| Our YARA pack | Hand-written rules | Direct files in `rules/yara/` |
| Community YARA | [YARA-Forge](https://github.com/YARAHQ/yara-forge), [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) (check licenses) | Git clone / download into `rules/yara/community/` |
| ClamAV health | `PING` + age of daily.cvd | Our healthcheck extension |

- [x] Expand first-party YARA rules (office / ELF / droppers + severity tags)
- [x] Optional community rule pack script (`scripts/fetch_community_yara.sh`)
- [x] ClamAV signature freshness hint in `/v1/health`
- [x] Automated tests (pytest unit) — free

**Outcome:** Internal pilot-ready stack, still 100% free/self-hosted.

**Suggested Compose after Phase 1:**

```text
api · worker · redis · clamav
(+ optional: nginx, prometheus, grafana, minio)
```

---

## Phase 1.5 — More free local engines (Docker or direct)

Still **no purchase**. Add adapters behind the same `ScanEngine` interface.

### Engines / tools we can install ourselves

| Engine / tool | Cost | Install | Best for | Priority |
|---------------|------|---------|----------|----------|
| **Linux Malware Detect (LMD)** | Free | Direct install script / our Dockerfile; uses ClamAV | Linux/web shells | High if web malware is in scope |
| **Community YARA packs** | Free | Git/files into rules dir | Broad static patterns | High |
| **oletools** (olevba, …) | Free | `pip install oletools` | Office macros | Medium |
| **CAPA** (Mandiant) | Free | Binary / Docker / pip ecosystem | PE capability labels | Medium |
| **FLOSS** (Mandiant) | Free | Binary / pip `flare-floss` | Obfuscated strings | Done (optional engine) |
| **ssdeep / tlsh** | Free | apt/pip | Fuzzy hash similarity | Medium |
| **ExifTool** | Free | apt / Docker | Metadata anomalies | Low |
| **Paranoya / Loki-style IOC+YARA** | Free | Docker `c0m4r/paranoya` or upstream Loki | Extra IOC/YARA service | Optional |
| **Windows Defender scan CLI** | Free* | Linux container patterns (see MalwareMultiScan); Windows host easier | Windows malware | Optional research |
| Hash cache (Redis) | Free | Same Redis as Phase 1 | Skip repeat SHA256 | High |
| **Stronger precheck** (image↔MIME) | Free | Our code | Disguised `.png`/`.jpg` executables | Done |
| **`pefile`** | Free (MIT) | `pip install pefile` | PE overlay / W+X / embedded MZ | Done |
| **Detect It Easy (DiE)** | Free | CLI in API image | Packer / compiler / type ID | Employer pick |
| **Manalyze** | Free (GPLv3) | Binary / build in image | Suspicious PE static indicators | Employer pick |
| **pdfid / pdf-parser** or **peepdf** | Free | apt / pip / scripts | Malicious PDF | Employer pick |
| **binwalk** | Free | apt / pip | Embedded / polyglot payloads | Employer pick |
| **ThreatFox** (abuse.ch) | Free Auth-Key | HTTPS client | Extra hash/IOC intel | Employer pick |

Employer-facing catalog (gaps, overlap, effort): [TOOLS.en.md](TOOLS.en.md) §5c.

\*Defender tooling availability/licensing for server automation must be verified per environment; prefer documented free CLI paths only.

### Tasks

- [x] `rules/yara/community/` + fetch helper script
- [x] `oletools` engine for Office / VBA macros
- [x] Pre-check engine + controlled archive member scan (see CORE_DETECTION)
- [x] Run `precheck` on extracted ZIP/TAR members (local; cheap disguise / entropy signals)
- [ ] abuse.ch / YARAify hash lookup on archive members (**deferred** — outer file only today; revisit with a per-scan member lookup budget)
- [x] LMD adapter (`maldet` subprocess) — https://github.com/rfxn/linux-malware-detect
- [x] CAPA engine (`capa -j` / flare-capa optional)
- [x] FLOSS engine (`floss -j` / flare-floss optional)
- [x] abuse.ch MalwareBazaar hash lookup (Auth-Key; no upload)
- [x] SHA256 scan-result cache + local allowlist/denylist (JSON files; Redis optional later)
- [x] Fuzzy hash fields on `FileInfo` (ssdeep/tlsh; optional libs)
- [x] Corpus benchmark script for employer demos
- [x] ClamAV signature freshness in `/v1/health`
- [ ] Optional Paranoya/Loki sidecar in Compose (**deferred** — revisit only if a second IOC daemon is required)
- [ ] ExifTool metadata engine (**deferred** — revisit for metadata-focused cases)
- [ ] Extra ClamAV community signature feeds (**deferred** — after license/trust review)
- [x] Stronger `precheck` (image/doc disguise ↔ PE/ELF; double-extension names)
- [x] `pefile` soft PE structure engine
- [ ] Remaining employer-pick candidates ([TOOLS.en.md](TOOLS.en.md) §5c): DiE; Manalyze; PDF tools; binwalk; optional ThreatFox / YARA-X / NSRL — **not started until chosen**
- [x] Verdict sensitivity modes (`lenient` / `balanced` / `strict`)
- [x] Corpus folder README + benchmark `--sensitivity`
- [~] **Exploit-DB** (https://gitlab.com/exploit-database/exploitdb) — **evaluated, not adopted as an engine** (pentester exploit/PoC archive; optional CVE reference only). See [TOOLS.en.md](TOOLS.en.md) §5b

**Outcome:** Stronger local coverage without any paid API or commercial AV license.

---

## Phase 2 — Free / freemium remote intel (then paid cloud)

Prefer **free lookups we can call without buying a product**, still behind the same engine interface. Keep `allow_cloud_upload=false` by default.

### 2.A — Free / research-friendly (start here)

| Service | Cost model | Install? | Use in FileScan |
|---------|------------|----------|-----------------|
| **abuse.ch** (MalwareBazaar, ThreatFox, …) | Free / fair use; Auth-Key | None (HTTPS client) | Hash / IOC reputation |
| **YARAify** (abuse.ch) | Community free / fair use | None | Extra YARA/Clam match online |
| **CIRCL / other free hash DBs** | Free public APIs (check ToS) | None | Hash lookup only |
| Self-kept hash denylist | Free | Our Redis/Postgres | Local intel from past scans |

- [x] MalwareBazaar hash-only reputation (`abusech`; never upload)
- [x] abuse.ch Auth-Key via env (`FILESCAN_ABUSECH_AUTH_KEY`)
- [x] YARAify hash lookup engine (`yaraify`; fair use / research)
- [x] Nested archive expansion (`FILESCAN_ARCHIVE_MAX_DEPTH`, default 2)
- [x] Fuzzy similarity vs denylist refs + cached malicious samples
- [ ] Local denylist/allowlist of SHA256 in Redis (optional later)

### 2.B — Employer cloud (only if free tier is not enough)

| Service | Notes |
|---------|-------|
| VirusTotal | Often paid for serious API volume; file upload may share samples |
| OPSWAT MetaDefender Cloud | Enterprise; paid |

- [ ] VirusTotal engine (hash → upload only if `allow_cloud_upload=true`)
- [ ] MetaDefender engine (same privacy flags)
- [ ] Document retention / sharing policy for the employer

**Outcome:** Cloud enrichment optional; free hash intel first; API unchanged.

---

## Phase 3 — Paid commercial AV (last resort)

Only after Phases 0–1.5 (and ideally 2.A) are measured.

Until then, squeeze more from **free installable** engines (Phase 1.5).

| Path | When |
|------|------|
| Stay on ClamAV + YARA + LMD + oletools + CAPA | Default |
| Buy 1 commercial engine | Clear gap on Windows PE / employer requirement |

Candidates if purchasing later: Microsoft Defender (licensed endpoint/server products), Sophos / ESET / Bitdefender / Kaspersky (Linux/file or SDK).

- [ ] Shortlist 1–2 vendors with employer **after** free corpus report
- [ ] License + Docker/CLI adapter
- [ ] A/B vs free stack on the same samples

**Outcome:** Paid adapter is optional; free stack remains the baseline.

---

## Phase 4 — Productization with free stack

Still prefer free software we host ourselves.

| Feature | Free approach |
|---------|----------------|
| Demo / admin UI | Simple static HTML, **Streamlit**, or lightweight React — our code |
| Webhooks | Our FastAPI background tasks |
| Multi-tenant API keys | Postgres (**Docker `postgres:16`**) + our code |
| Retention / delete API | Our code + volume/MinIO lifecycle |
| Dashboards | **Grafana** + Prometheus metrics |
| Benchmark report | Script + Markdown/PDF for employer |

- [ ] Demo UI (scan upload + result view)
- [ ] Webhooks on scan complete
- [ ] Postgres for keys/history (Compose service)
- [ ] Retention / delete endpoints
- [ ] Grafana dashboard for scan volume, verdict mix, engine latency
- [ ] Employer benchmark report (free tools only first page)

**Outcome:** Usable internal product without mandatory paid SaaS.

---

## Free software catalog (quick reference)

Installable by us today or next phases:

| Software | Role | Docker | Direct |
|----------|------|--------|--------|
| ClamAV | AV signatures | Yes (`clamav/clamav`) | apt `clamav` / `clamav-daemon` |
| YARA + yara-python | Custom rules | In API image | pip + libyara |
| Redis | Queue / cache | Yes | apt |
| Nginx / Caddy | Reverse proxy | Yes | apt |
| Prometheus + Grafana | Metrics | Yes | apt/binaries |
| MinIO | S3-compatible storage | Yes | binary |
| Postgres | Keys / history | Yes | apt |
| LMD | Linux/web malware | Custom Dockerfile | Install script |
| oletools | Office macros | In API image | pip |
| CAPA / FLOSS | PE / strings analysis | Optional image | Mandiant releases |
| ssdeep / tlsh | Fuzzy hashing | In API image | apt/pip |
| community YARA packs | Extra detections | Volume mount | git clone |
| abuse.ch APIs | Free hash/YARA intel | N/A (HTTP) | API key only |

---

## Suggested pitch to the employer

1. **Now (free, installed by us):** ClamAV + YARA + our API (Docker Compose)  
2. **Next (still free):** Redis workers, API key, more YARA, LMD, oletools, optional CAPA  
3. **Then (free remote):** abuse.ch / YARAify hash intel — no file upload by default  
4. **Only if needed:** VirusTotal/MetaDefender keys or **one** commercial AV  

Do **not** buy commercial AV before the free self-hosted stack is measurable.

---

## Success metrics

| Metric | Target (pilot) |
|--------|----------------|
| Scan latency (local free engines, <10MB) | < 5s typical |
| Always-on free engines | ≥ 2 (ClamAV + YARA); stretch ≥ 3 after 1.5 |
| Cost of Phase 0–1.5 | $0 license (infra/electricity only) |
| False positive rate on clean corpus | Track and tune YARA |
| Cloud upload | Off by default |

Related: [OVERVIEW.en.md](OVERVIEW.en.md) · [ARCHITECTURE.en.md](ARCHITECTURE.en.md) · [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md) · [DEPLOY.en.md](DEPLOY.en.md)

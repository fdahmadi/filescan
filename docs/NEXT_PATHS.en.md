# FileScan — Paths A / B (completed) and what remains

Historical delivery tracks for the free pilot. **Current snapshot:** [STATUS.en.md](STATUS.en.md).

---

## Path A — Detection strength (free tools) ✅

| Item | Status |
|------|--------|
| MIME allowlist / denylist (`FILESCAN_MIME_*`) | Done |
| CAPA inside API image (`flare-capa` + `capa-rules`) | Done |
| LMD (`maldet`) inside API image when install succeeds | Done (best-effort) |
| Community YARA fetch (opt-in curated Neo23x0 subset) | `scripts/fetch_community_yara.sh` |
| FLOSS inside API image (`flare-floss`) | Done |
| First-party YARA expansion (office / ELF / droppers / webshells / LOLBAS) | Done |
| Verdict sensitivity `lenient` / `balanced` / `strict` | Done |
| abuse.ch Auth-Key for `abusech` + `yaraify` | Optional — https://auth.abuse.ch/ → `FILESCAN_ABUSECH_AUTH_KEY` |
| ClamAV + API via Compose | `docker compose up --build -d` |

### Intentionally deferred (still free) — do not build yet

| Item | Why deferred | When to reconsider |
|------|----------------|--------------------|
| ExifTool metadata engine | Weak verdict signal for most malware pilots | Metadata-focused requirements |
| Loki / Paranoya Compose sidecar | Heavy; YARA+LMD already cover IOC/static | Dedicated second IOC daemon requested |
| Extra ClamAV community signature feeds | License/trust review | After legal/trust sign-off |
| abuse.ch / YARAify on archive members | Outer upload hash only; per-member remote lookups cost latency + fair-use quota | Known malware packed in ZIP/TAR is a demo gap and a member-lookup budget is defined |
| Exploit-DB / SearchSploit | **Not deferred — rejected as scan engine.** Exploit/PoC archive for pentesters; wrong problem vs file verdicts; live attack material vs safe-sample policy | Only optional CVE **reference** links if reports need enrichment — never match uploads against the DB ([TOOLS.en.md](TOOLS.en.md) §5b) |

### Candidate free engines — employer pick

Catalog + rationale: [TOOLS.en.md](TOOLS.en.md) §5c · snapshot: [STATUS.en.md](STATUS.en.md).

| Status | Candidate | Gap |
|--------|-----------|-----|
| ✅ Done | Stronger `precheck` (image ↔ MIME / double-extension) | Disguised executables named like images/docs |
| ✅ Done | `pefile` soft engine | PE overlay / W+X / TLS / embedded MZ in resources |
| Pick later | Detect It Easy (DiE) | Packer / compiler / type ID |
| Pick later | Manalyze | Suspicious PE static indicators |
| Pick later | pdfid / pdf-parser or peepdf | Malicious PDF |
| Pick later | binwalk | Embedded / polyglot payloads |
| Later | ThreatFox, YARA-X, NSRL | Extra intel / newer YARA / known-good FP reduction |

Remaining rows: add only after an employer chooses a gap; wire as a normal `ScanEngine` adapter.

---

## Path B — Usable pilot API ✅

| Item | Status |
|------|--------|
| `X-API-Key` on scan endpoints | `FILESCAN_API_KEYS` |
| Per-key rate limiting | `FILESCAN_RATE_LIMIT_PER_MINUTE` |
| OpenAPI / Swagger at `/docs` | Done |
| Demo UI at `/ui` | Done |
| Sensitivity on scan + UI | Done |
| Per-scan `use_remote_intel` (skip abuse.ch/YARAify) | Done |
| Health at `/v1/health` (no key) | Done |
| Async Redis queue | **Later** (not required for pilot) |

### Quick test (port **8001**)

- UI: http://127.0.0.1:8001/ui/ (key `dev-demo-key`)  
- Swagger: http://127.0.0.1:8001/docs  
- Scripted demo: [DEMO.en.md](DEMO.en.md)

```bash
export API_KEY=dev-demo-key
curl -sS http://127.0.0.1:8001/v1/health | jq
curl -sS -H "X-API-Key: $API_KEY" -F "file=@./testdata/corpus/eicar.txt" \
  -F "sensitivity=balanced" http://127.0.0.1:8001/v1/scan | jq
```

---

## Recommended after A/B (see STATUS)

1. Run the demo runbook with stakeholders  
2. Change API keys before shared/server use  
3. Structured logging + upload TTL (ops)  
4. Redis/async / cloud AV only if requirements demand  

Related: [DEPLOY.en.md](DEPLOY.en.md) · [CORE_DETECTION.en.md](CORE_DETECTION.en.md) · [ROADMAP.en.md](ROADMAP.en.md)

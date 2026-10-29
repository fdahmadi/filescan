# FileScan — Status (done / next / deferred)

Single snapshot of where the project stands. Prefer this page over older “active focus” wording in other docs.

Last aligned with the free pilot stack (Compose `api` + `clamav`, demo UI, sensitivity, optional abuse.ch).

---

## Done (free pilot — usable now)

| Area | What |
|------|------|
| Compose | `api` + `clamav` only (host networking; API `:8001`) |
| Engines | precheck (incl. image↔executable disguise), ClamAV, YARA, oletools, LMD, CAPA, FLOSS, pefile, archive (ZIP/TAR members re-scanned), fuzzy, hash cache / allow-deny |
| Remote (optional) | `abusech` + `yaraify` hash lookup — Auth-Key from https://auth.abuse.ch/ |
| API | `GET /v1/health`, `POST /v1/scan` (+ `sensitivity`), `GET /v1/scan/{id}` |
| Pilot access | `X-API-Key`, rate limit, Swagger `/docs` |
| Demo UI | `/ui` — upload, sensitivity, colored verdict, short summary |
| Rules | First-party YARA + curated community pack / fetch script |
| Verdict | Hard vs soft engines; `lenient` / `balanced` / `strict` |
| Docs | Architecture, deploy, tools catalog, detection core, demo runbook |
| Tests | pytest unit suite; `scripts/benchmark_corpus.py`; `scripts/smoke_scan.sh` |

**Try it:** [DEMO.en.md](DEMO.en.md) · http://127.0.0.1:8001/ui/  
**Test samples (employer write-up):** [TEST_SAMPLES.en.md](TEST_SAMPLES.en.md)  
**Files on disk:** [testdata/manual_check/](../testdata/manual_check/) (`clean/` + `should_detect/` + `SCAN_RESULTS.md`)

---

## Recommended next (not detection engines)

| Priority | Item | Why |
|----------|------|-----|
| 1 | Run the [demo runbook](DEMO.en.md) end-to-end | Validate for stakeholder meeting |
| 2 | Rotate `FILESCAN_API_KEYS` off `dev-demo-key` before any shared/server deploy | Pilot hygiene |
| 3 | Structured scan logging (verdict, duration, engines) | Ops / debugging |
| 4 | Upload / results TTL cleanup | Disk hygiene on long-running hosts |
| 5 | Keep corpus samples updated when adding YARA | Regression confidence |

Detection core itself is **not** blocked on new free engines unless a coverage gap appears in demos.

---

## Deferred on purpose (free, low priority)

| Item | Why wait |
|------|----------|
| ExifTool engine | Weak verdict signal for most pilots |
| Loki / Paranoya sidecar | Heavy; overlaps YARA + LMD |
| Extra ClamAV community feeds | License / trust review first |
| abuse.ch / YARAify on archive members | Outer-file hash only; per-member HTTPS × N is heavier |

See [NEXT_PATHS.en.md](NEXT_PATHS.en.md).

---

## Candidate free engines (employer pick — not built yet)

Pilot works without these. Full write-up: [TOOLS.en.md](TOOLS.en.md) §5c.  
**Shipped from that list:** stronger `precheck` disguise checks · `pefile` engine.

| Priority | Candidate | Gap |
|----------|-----------|-----|
| 1 | Detect It Easy (DiE) | Packer / compiler / type ID |
| 2 | Manalyze | Suspicious PE static indicators |
| 3 | pdfid / pdf-parser or peepdf | Malicious PDF (oletools does not cover PDF) |
| 4 | binwalk | Embedded payloads / polyglots |
| Later | ThreatFox, YARA-X, NSRL, extra Clam feeds | Extra intel / engine / FP reduction / AV breadth |

---

## Evaluated — not a scan engine

| Item | Decision |
|------|----------|
| **Exploit-DB** (gitlab.com/exploit-database/exploitdb) | Archive of public exploits/PoCs + SearchSploit. Useful for pentesters, **not** for upload verdicts. Do not integrate as an engine. Optional later: CVE report link only. Details: [TOOLS.en.md](TOOLS.en.md) §5b |

---

## Later (product / paid)

| Item | Notes |
|------|--------|
| Redis + async workers | Large files / queue |
| Nginx / TLS | Public exposure |
| Prometheus / Grafana | Observability |
| VirusTotal / MetaDefender / commercial AV | Employer keys / licenses |

Full phased map: [ROADMAP.en.md](ROADMAP.en.md).

---

## Doc map (what to read)

| Need | Doc |
|------|-----|
| Employer one-pager | [OVERVIEW.en.md](OVERVIEW.en.md) |
| This status page | [STATUS.en.md](STATUS.en.md) |
| How engines connect | [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md) · [TOOLS.en.md](TOOLS.en.md) |
| Tools catalog + evaluated/rejected + employer candidates | [TOOLS.en.md](TOOLS.en.md) (§5 deferred, §5b Exploit-DB, §5c candidates) |
| Server install | [DEPLOY.en.md](DEPLOY.en.md) |
| Verdict / sensitivity / abuse.ch | [CORE_DETECTION.en.md](CORE_DETECTION.en.md) |
| 3-minute demo | [DEMO.en.md](DEMO.en.md) |
| Long-term phases | [ROADMAP.en.md](ROADMAP.en.md) |

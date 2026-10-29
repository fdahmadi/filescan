# FileScan — Project Overview (for employer / team)

## What is this project?

A **multi-engine malware scanning API**: a file is uploaded, several engines inspect it independently, and a single report (`verdict`) is returned. A small **demo UI** is included for stakeholder walkthroughs.

## Status snapshot

| | |
|--|--|
| Free detection core + pilot API + demo UI | **Done** |
| Recommended now | Run [DEMO.en.md](DEMO.en.md); see [STATUS.en.md](STATUS.en.md) |
| Deferred on purpose | ExifTool, Loki/Paranoya, extra Clam feeds, remote intel on archive members |
| Candidate free engines (pick later) | DiE, Manalyze, PDF tools, binwalk, … — [TOOLS.en.md](TOOLS.en.md) §5c (`precheck` disguise + `pefile` already shipped) |
| Evaluated, not adopted | Exploit-DB (not a file-scan engine — see [TOOLS.en.md](TOOLS.en.md) §5b) |
| Later | Redis/async, Grafana, paid cloud/AV |

## What is implemented (free)

1. **ClamAV** — antivirus daemon in Docker  
2. **YARA** — first-party + curated community rules  
3. **precheck** — entropy, dangerous extensions, image/doc disguise ↔ executable content  
4. **oletools / LMD / CAPA / FLOSS / pefile** — Office, Linux/web, PE capability, obfuscated strings, PE structure heuristics  
5. **Orchestrator** — verdict with `lenient` / `balanced` / `strict` sensitivity  
6. **API** — `/v1/health`, `/v1/scan`, `/v1/scan/{id}` + `X-API-Key` + rate limit + Swagger  
7. **Demo UI** — http://127.0.0.1:8001/ui/  
8. **Optional remote** — abuse.ch MalwareBazaar + YARAify (**hash only**; Auth-Key at https://auth.abuse.ch/)  

Details: [CORE_DETECTION.en.md](CORE_DETECTION.en.md) · [TOOLS.en.md](TOOLS.en.md) · [STATUS.en.md](STATUS.en.md)

## Completed delivery paths

| Path | Focus | Status |
|------|--------|--------|
| Core steps 1–6 | Local free detection | ✅ |
| **A** / **A+** | MIME, Docker CAPA/LMD/FLOSS, YARA polish | ✅ |
| **B** | Pilot API + Swagger + demo UI + sensitivity | ✅ |

## What we are not doing yet

| Bucket | Items |
|--------|--------|
| Deferred (free, optional) | ExifTool, Loki/Paranoya sidecar, extra ClamAV community feeds, abuse.ch/YARAify on archive members |
| Candidate free engines (employer pick) | DiE; Manalyze; pdfid/peepdf; binwalk; optional ThreatFox / YARA-X / NSRL — details [TOOLS.en.md](TOOLS.en.md) §5c (`precheck` disguise + `pefile` done) |
| Evaluated / not a scan engine | Exploit-DB / SearchSploit — pentester exploit archive; optional CVE reference only |
| Later (ops / product) | Structured logging TTL, Redis async, Nginx/TLS, Grafana |
| Later (paid) | VirusTotal, MetaDefender, commercial AV |

## abuse.ch (optional)

| URL | Role |
|-----|------|
| https://auth.abuse.ch/ | **Get Auth-Key** |
| https://bazaar.abuse.ch/ | MalwareBazaar UI |
| https://yaraify.abuse.ch/ | YARAify UI |

Set `FILESCAN_ABUSECH_AUTH_KEY` in `.env`. Local engines work without it.

## Run

```bash
docker compose up --build -d
# Demo UI: http://127.0.0.1:8001/ui/   (API key: dev-demo-key)
# Health:  http://127.0.0.1:8001/v1/health
# Swagger: http://127.0.0.1:8001/docs
```

Walkthrough: [DEMO.en.md](DEMO.en.md)  
Test samples + results: [TEST_SAMPLES.en.md](TEST_SAMPLES.en.md)  
Deploy: [DEPLOY.en.md](DEPLOY.en.md)  
Architecture: [ARCHITECTURE.en.md](ARCHITECTURE.en.md)  
Roadmap: [ROADMAP.en.md](ROADMAP.en.md)

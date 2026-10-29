# FileScan

Multi-engine malware scanning API for research / employer pilots.

**Done (free pilot):** ClamAV + YARA (+ community) + LMD + CAPA + FLOSS + oletools + optional abuse.ch hash intel + demo UI + sensitivity  
**Next:** stakeholder demo → ops hardening (real API keys, logging, upload TTL) — [docs/STATUS.en.md](docs/STATUS.en.md)  
**Deferred on purpose:** ExifTool, Loki/Paranoya, extra Clam feeds  
**Later:** Redis/async, Grafana, VirusTotal / MetaDefender, commercial AV  

## Docs

Index: [docs/README.md](docs/README.md) · **Status:** [docs/STATUS.en.md](docs/STATUS.en.md)

| Topic | Document |
|-------|----------|
| Overview | [OVERVIEW.en.md](docs/OVERVIEW.en.md) |
| Demo runbook (3 min) | [DEMO.en.md](docs/DEMO.en.md) |
| Test samples + scan results | [TEST_SAMPLES.en.md](docs/TEST_SAMPLES.en.md) |
| Deploy | [DEPLOY.en.md](docs/DEPLOY.en.md) |
| Detection core | [CORE_DETECTION.en.md](docs/CORE_DETECTION.en.md) |
| Tools & libraries | [TOOLS.en.md](docs/TOOLS.en.md) |
| How it works / ClamAV | [HOW_IT_WORKS.en.md](docs/HOW_IT_WORKS.en.md) |
| Architecture | [ARCHITECTURE.en.md](docs/ARCHITECTURE.en.md) |
| Roadmap | [ROADMAP.en.md](docs/ROADMAP.en.md) |
| Paths A/B | [NEXT_PATHS.en.md](docs/NEXT_PATHS.en.md) |

## Quick start (Docker)

```bash
cp -n .env.example .env
# Optional: FILESCAN_ABUSECH_AUTH_KEY from https://auth.abuse.ch/
docker compose up --build -d
```

First ClamAV start can take a few minutes while signatures download.  
Compose serves the API on **host port 8001** (host networking).

- Demo UI: http://127.0.0.1:8001/ui/  
- Health: http://127.0.0.1:8001/v1/health  
- Swagger: http://127.0.0.1:8001/docs  
- API key (pilot default): `dev-demo-key` (`FILESCAN_API_KEYS`)

```bash
curl -sS -H "X-API-Key: dev-demo-key" \
  -F "file=@./testdata/corpus/eicar.txt" \
  -F "sensitivity=balanced" \
  http://127.0.0.1:8001/v1/scan | jq
```

```bash
BASE_URL=http://127.0.0.1:8001 ./scripts/smoke_scan.sh
PYTHONPATH=. python scripts/benchmark_corpus.py
```

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Redirects to demo UI |
| GET | `/ui/` | Stakeholder demo UI |
| GET | `/v1/health` | Service + engine health |
| POST | `/v1/scan` | Upload + scan (`sensitivity` form field optional) |
| GET | `/v1/scan/{id}` | Fetch stored result |
| GET | `/docs` | OpenAPI / Swagger |

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# FILESCAN_CLAMAV_ENABLED=false  # if no clamd
PYTHONPATH=. uvicorn app.main:app --reload --port 8000
PYTHONPATH=. pytest -q
```

## Project layout

```
app/           # API, engines, services, static/ui
rules/yara/    # First-party + community YARA
testdata/      # Demo / benchmark corpus
docs/          # Documentation
scripts/       # smoke_scan, benchmark_corpus, fetch_community_yara
```

## Security note

Do not expose this API publicly without authentication, rate limits, TLS, and upload safeguards. Treat every upload as untrusted; engines must not execute samples. Change `dev-demo-key` before any shared deployment.

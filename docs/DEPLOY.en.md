# FileScan — Server deployment guide

How to run FileScan on a Linux server with Docker Compose (recommended).  
Status / next steps: [STATUS.en.md](STATUS.en.md) · Stakeholder demo: [DEMO.en.md](DEMO.en.md)

---

## 1) What runs on the server

| Container | Role | Host port (default) |
|-----------|------|---------------------|
| `api` | FastAPI + engines (host network) | `8001` → HTTP API |
| `clamav` | `clamd` (host network) | `3310` on host loopback/LAN stack |

Clients talk to the **API** on port `8001` (or via a reverse proxy on `80`/`443`).  
Both services use **`network_mode: host`** so the API reaches ClamAV at `127.0.0.1:3310` without Docker port-proxy.  
Reason: on some Linux hosts, Docker bridge port-publish returns empty TCP replies; host networking keeps the pilot usable.

```
Internet / LAN
      │
      ▼
[Nginx/Caddy optional] ──► [api :8001 host] ──TCP──► [clamav :3310 host]
```

**Hardening:** firewall `3310` and `8001` on public servers; prefer reverse proxy + TLS for the API.

### What runs where (Compose has only two services)

Compose intentionally starts **only** `api` + `clamav`. You do **not** need a container per scanner.

| Piece | Where it runs |
|-------|----------------|
| ClamAV (`clamd`) | Separate `clamav` service |
| FastAPI + orchestrator | Inside `api` image |
| YARA, precheck, oletools, archive, cache, fuzzy | Inside `api` (Python) |
| LMD (`maldet`), CAPA (+ capa-rules), FLOSS | Installed **inside** the `api` image at build time |
| abuse.ch / YARAify | Remote HTTPS APIs (no Compose service; need Auth-Key) |
| Redis / Nginx / Grafana | **Not** in Compose yet (later roadmap) |

`depends_on: clamav` only means: start `api` after ClamAV is healthy — it is not a third service.

---

## 2) Server requirements

| Item | Recommendation |
|------|----------------|
| OS | Ubuntu 22.04+ / Debian 12+ (or any Linux with Docker) |
| Docker | Docker Engine + Docker Compose plugin (`docker compose`) |
| RAM | **≥ 2 GB** (ClamAV signatures need memory; 4 GB safer) |
| Disk | **≥ 5 GB** free (images + ClamAV DB + uploads) |
| CPU | 1+ vCPU (2+ better for parallel uploads later) |
| Network | Outbound HTTPS for first image/signature download |

Install Docker (Ubuntu example):

```bash
# Official docs: https://docs.docker.com/engine/install/
sudo apt update
sudo apt install -y ca-certificates curl
# … follow Docker’s current install steps for your distro …
docker --version
docker compose version
```

Add your user to the `docker` group (then re-login):

```bash
sudo usermod -aG docker "$USER"
```

---

## 3) Get the project onto the server

### Option A — Git clone

```bash
cd /opt   # or any path you prefer
sudo mkdir -p /opt/filescan && sudo chown "$USER":"$USER" /opt/filescan
cd /opt/filescan
git clone <YOUR_REPO_URL> .
```

### Option B — Copy files (scp/rsync)

```bash
rsync -avz --exclude .venv --exclude .git \
  ./filescan/ user@SERVER:/opt/filescan/
```

On the server:

```bash
cd /opt/filescan
ls   # expect docker-compose.yml, Dockerfile, app/, rules/, …
```

---

## 4) Production-oriented Compose tips

Default Compose runs **api + clamav with host networking** (API on **8001**, ClamAV on **3310**).  
**On a public server:** put Nginx/Caddy in front, firewall `8001`/`3310`, and restrict ClamAV to trusted hosts.---

## 5) Start the stack

```bash
cd /opt/filescan

# Build API image and start both services in background
docker compose up --build -d
```

### First boot (important)

ClamAV downloads virus signatures the first time. This can take **several minutes**.

Watch health:

```bash
docker compose ps
docker compose logs -f clamav
```

Wait until `clamav` is **healthy**, then check the API:

```bash
curl -sS http://127.0.0.1:8001/v1/health | jq
```

Expected: `"status": "ok"` (or `"degraded"` if optional remote engines lack an Auth-Key). ClamAV / YARA / LMD / CAPA should show healthy when installed.

Demo UI (upload → verdict):

`http://SERVER_IP:8001/ui/`

Swagger (API explorer):

`http://SERVER_IP:8001/docs`

---

## 6) Smoke test on the server

```bash
cd /opt/filescan
chmod +x scripts/smoke_scan.sh
BASE_URL=http://127.0.0.1:8001 ./scripts/smoke_scan.sh
```

Or manually:

```bash
# EICAR test string (safe antivirus test file content)
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

curl -sS -H "X-API-Key: dev-demo-key" -F "file=@/tmp/eicar.txt;filename=eicar.txt" \
  http://127.0.0.1:8001/v1/scan | jq
```

You should see `verdict: "malicious"` (ClamAV and/or YARA).

---

## 7) Useful day-2 commands

```bash
cd /opt/filescan

# Status
docker compose ps

# Logs
docker compose logs -f api
docker compose logs -f clamav

# Restart after code/rules change
docker compose up --build -d

# Stop
docker compose down

# Stop and remove volumes (DESTROYS ClamAV DB + stored scan results)
docker compose down -v
```

Update YARA rules: edit files under `rules/yara/`, then recreate the API container (rules are bind-mounted read-only):

```bash
docker compose up -d --force-recreate api
```

Note: YARA rules are compiled at API process start — recreate/restart `api` after rule changes.

---

## 8) Firewall

Example with `ufw` (only SSH + API, or only SSH if using a reverse proxy on the same host):

```bash
sudo ufw allow OpenSSH
sudo ufw allow 8000/tcp    # only if clients hit the API directly
# sudo ufw allow 80/tcp
# sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
```

**Do not** open `3310/tcp` to the internet.

---

## 9) Optional reverse proxy (Nginx)

Example: TLS termination later; for now HTTP proxy to the API.

```nginx
server {
    listen 80;
    server_name filescan.example.com;

    client_max_body_size 35m;   # keep ≥ FILESCAN_MAX_UPLOAD_BYTES

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }
}
```

Then bind Compose API to `127.0.0.1:8000` only (see section 4).

---

## 10) Environment variables

Compose already sets the main ClamAV/YARA paths for Docker networking.

You can extend `api.environment` in `docker-compose.yml` or use an env file. Prefix is `FILESCAN_`.

| Variable | Typical server value | Notes |
|----------|----------------------|-------|
| `FILESCAN_CLAMAV_HOST` | `clamav` | Docker service name |
| `FILESCAN_CLAMAV_PORT` | `3310` | Internal |
| `FILESCAN_CLAMAV_ENABLED` | `true` | |
| `FILESCAN_YARA_ENABLED` | `true` | |
| `FILESCAN_YARA_RULES_DIR` | `/app/rules/yara` | Inside container |
| `FILESCAN_MAX_UPLOAD_BYTES` | `33554432` (32 MiB) | Raise if needed |
| `FILESCAN_UPLOAD_DIR` | `/tmp/filescan/uploads` | On Docker volume |
| `FILESCAN_RESULTS_DIR` | `/tmp/filescan/results` | On Docker volume |

Local `.env.example` uses `127.0.0.1` for ClamAV — that is for **non-Docker** local runs, not for Compose on the server.

---

## 11) Security checklist (current MVP)

FileScan MVP has **no API authentication** yet. Treat it as an **internal** service until Phase 1 auth lands.

- [ ] Do not expose ClamAV port `3310` publicly
- [ ] Prefer reverse proxy + bind API to localhost
- [ ] Firewall: only required ports
- [ ] Put the API behind VPN / private network if possible
- [ ] Limit upload size (`FILESCAN_MAX_UPLOAD_BYTES` + proxy `client_max_body_size`)
- [ ] Keep Docker images and ClamAV signatures updated (`docker compose pull` / recreate)
- [ ] Do not run untrusted samples outside the scanner; engines must not execute uploads

---

## 12) Troubleshooting

| Symptom | What to check |
|---------|----------------|
| `api` waits / unhealthy | `docker compose logs clamav` — signatures still downloading? |
| Health: clamav unreachable | Is `FILESCAN_CLAMAV_HOST=127.0.0.1` and port `3310` published? Is clamav healthy? |
| Empty reply on published bridge port | Expected on some hosts — Compose uses host network on `:8001` |
| CAPA unhealthy / missing rules | Image must include `/opt/capa-rules`; rebuild API image |
| Build fails (apt/DNS) | Try `docker build --network=host`; check outbound DNS/HTTP |
| 413 on upload | Raise `FILESCAN_MAX_UPLOAD_BYTES` and proxy body size |
| 401 on scan | Send `X-API-Key` matching `FILESCAN_API_KEYS` |
| YARA rules not applied | Restart/recreate `api` after editing `rules/yara/` |
| Out of memory | Increase RAM; ClamAV is memory-heavy |

```bash
curl -sS http://127.0.0.1:8001/v1/health | jq
docker compose ps
docker compose logs --tail=100 api clamav
```

---

## 13) Optional abuse.ch Auth-Key (hash intel)

Not required for local ClamAV/YARA demos. Enables engines `abusech` + `yaraify` (hash lookup only; **no file upload**).

| URL | Purpose |
|-----|---------|
| https://auth.abuse.ch/ | **Get the free Auth-Key** (sign up / log in here) |
| https://bazaar.abuse.ch/ | MalwareBazaar UI |
| https://yaraify.abuse.ch/ | YARAify UI |
| https://mb-api.abuse.ch/api/v1 | MalwareBazaar API (default in `.env`) |
| https://yaraify-api.abuse.ch/api/v1 | YARAify API (default in `.env`) |

```bash
# 1) Get key from https://auth.abuse.ch/
# 2) Put in .env
FILESCAN_ABUSECH_AUTH_KEY=paste-key-here

# 3) Recreate API
docker compose up -d --force-recreate api

# 4) Health should no longer say Auth-Key not set for abusech/yaraify
curl -sS http://127.0.0.1:8001/v1/health | jq '.engines[] | select(.name=="abusech" or .name=="yaraify")'
```

Stakeholder demo script: [DEMO.en.md](DEMO.en.md).

---

## 14) Minimal copy-paste runbook

```bash
cd /opt/filescan
cp -n .env.example .env   # set FILESCAN_API_KEYS; optional FILESCAN_ABUSECH_AUTH_KEY from https://auth.abuse.ch/
docker compose up --build -d
docker compose ps
# wait until clamav is healthy (first time: several minutes)
curl -sS http://127.0.0.1:8001/v1/health | jq

# Scan requires X-API-Key when FILESCAN_API_KEYS is set (default in compose: dev-demo-key)
curl -sS -H "X-API-Key: dev-demo-key" -F "file=@./testdata/corpus/eicar.txt" \
  http://127.0.0.1:8001/v1/scan | jq
```

Demo UI: http://SERVER_IP:8001/ui/  
Swagger UI: http://SERVER_IP:8001/docs  

Path A/B notes: [NEXT_PATHS.en.md](NEXT_PATHS.en.md)

Related: [HOW_IT_WORKS.en.md](HOW_IT_WORKS.en.md) · [OVERVIEW.en.md](OVERVIEW.en.md) · [ROADMAP.en.md](ROADMAP.en.md) · [DEMO.en.md](DEMO.en.md)

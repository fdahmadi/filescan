# FileScan — 3-minute demo runbook

For the technical PM / stakeholder walkthrough. Stack must already be up (`docker compose up -d`).  
Project status: [STATUS.en.md](STATUS.en.md).  
Full sample catalog + recorded results: [TEST_SAMPLES.en.md](TEST_SAMPLES.en.md).

---

## Before you start

| Check | Command / URL |
|-------|----------------|
| API up | http://127.0.0.1:8001/v1/health |
| Demo UI | http://127.0.0.1:8001/ui/ |
| API key in UI | prefilled `dev-demo-key` (change only if you changed `.env`) |
| Samples | `testdata/corpus/` in the repo |

Optional (not required for this demo): free abuse.ch Auth-Key — see [below](#optional-abusech-auth-key).

---

## Script (~3 minutes)

### 1) Open the UI (30s)

1. Open http://127.0.0.1:8001/ui/
2. Leave **API key** as `dev-demo-key`
3. Leave **Sensitivity** on **Balanced**
4. Leave **Use remote hash intel** checked (or uncheck for local-only — hash never uploads the file either way)
5. Point at the footer: service status / healthy engines

Say: *“One upload, several free engines, one verdict — no cloud upload by default.”*

### 2) Clean file → expect `clean` (30s)

- Upload `testdata/corpus/clean.txt`
- Expect verdict **CLEAN**
- Summary: no engine flags (or only skipped)

### 3) EICAR → expect `malicious` (45s)

- Upload `testdata/corpus/eicar.txt`  
  (standard antivirus test string — safe, not real malware)
- Expect verdict **MALICIOUS**
- Point at **clamav** and/or **yara** in the engine list

Say: *“ClamAV signatures + our YARA rules agree on a known test sample.”*

### 4) Webshell-like sample → expect `malicious` (45s)

- Upload `testdata/corpus/webshell_sample.php`
- Expect **MALICIOUS** (YARA; other engines may add soft signals)
- Optionally show **Strict** vs **Lenient** once: same file, flip Sensitivity, Scan again — explain soft engines escalate only in Strict

### 5) Close (30s)

- Swagger for integrators: http://127.0.0.1:8001/docs  
- Tools list: [TOOLS.en.md](TOOLS.en.md)  
- Deploy later: [DEPLOY.en.md](DEPLOY.en.md)

Optional extra if time: `powershell_cradle.ps1` or `certutil_lolbas.cmd` from the same folder.

---

## Offline table (no UI)

```bash
cd /path/to/filescan
PYTHONPATH=. python scripts/benchmark_corpus.py
```

See [testdata/corpus/README.md](../testdata/corpus/README.md).

---

## Optional: abuse.ch Auth-Key

Remote **hash-only** lookups (`abusech` + `yaraify`). Files are **not** uploaded.

1. Open **https://auth.abuse.ch/** (official abuse.ch login / Auth-Key portal)
2. Create / sign in to an account
3. Obtain an **Auth-Key** for API use (MalwareBazaar / YARAify family)
4. Put it in `.env`:

```bash
FILESCAN_ABUSECH_AUTH_KEY=your-key-here
```

5. Recreate API:

```bash
docker compose up -d --force-recreate api
```

6. `/v1/health` should show `abusech` / `yaraify` healthy (no longer “Auth-Key not set”).

Related public sites (intel, not where you mint the key):

| Site | Role |
|------|------|
| https://auth.abuse.ch/ | **Get the Auth-Key here** |
| https://bazaar.abuse.ch/ | MalwareBazaar UI |
| https://yaraify.abuse.ch/ | YARAify UI |

Fair use / rate limits apply; see notices on auth.abuse.ch.

---

## Talking points (short)

- Free / self-hosted first: ClamAV, YARA, LMD, CAPA, FLOSS, oletools  
- Pilot API: `X-API-Key` + rate limit + demo UI  
- Sensitivity: local knob, no SaaS  
- Cloud AV / VT only later if coverage gaps remain  

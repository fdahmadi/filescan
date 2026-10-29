# Test corpus (local, free)

Small **synthetic** samples for demos and regression — not real malware implants.

For a larger hands-on pack with recorded live scan results, see also  
[`../manual_check/`](../manual_check/) (`clean/` + `should_detect/` + `SCAN_RESULTS.md`).

| File | Expected (typical, balanced) |
|------|------------------------------|
| `clean.txt` | `clean` |
| `eicar.txt` | `malicious` (ClamAV and/or YARA) |
| `webshell_sample.php` | `malicious` / `suspicious` via YARA |
| `powershell_cradle.ps1` | `malicious` / `suspicious` via YARA |
| `jsp_runtime_exec.jsp` | YARA webshell hit when rules load |
| `certutil_lolbas.cmd` | YARA living-off-the-land hit |

## What “corpus + benchmark” means

No separate product feature. It means:

1. Keep a folder of known samples (`testdata/corpus/`).
2. Run `scripts/benchmark_corpus.py` to print a table of **file → verdict → which engines fired**.

That shows the employer (and us) whether detection still works after rule/engine changes — locally, free, offline (script disables ClamAV/LMD/CAPA/remote by default).

```bash
PYTHONPATH=. python scripts/benchmark_corpus.py
PYTHONPATH=. python scripts/benchmark_corpus.py --sensitivity strict
```

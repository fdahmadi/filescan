# Sensitivity demo samples

Safe files that show how `lenient` / `balanced` / `strict` change the **final verdict** for the same bytes.

Hard AV hits (EICAR) stay `malicious` on every mode. Soft / packer-heuristic hits escalate to `malicious` only under **strict**.

| File | Signal type | lenient | balanced | strict |
|------|-------------|---------|----------|--------|
| `soft_php_echo.php` | Soft — precheck dangerous `.php` | suspicious | suspicious | **malicious** |
| `soft_high_entropy.bin` | Soft — precheck high entropy | suspicious | suspicious | **malicious** |
| `soft_photo.png.exe` | Soft — precheck double-extension disguise | suspicious | suspicious | **malicious** |
| `hard_linux_upx_elf` | Hard-suspicious — YARA UPX ELF sections | suspicious | suspicious | **malicious** |
| `hard_windows_upx.exe` | Hard-suspicious — YARA UPX PE section (+ CAPA) | suspicious | suspicious | **malicious** |
| `control_eicar.txt` | Hard infected — ClamAV + YARA | malicious | malicious | malicious |
| `control_clean.txt` | No signals | clean | clean | clean |

## Why only two different verdicts (not three)?

With the current aggregator, soft / hard-**suspicious** hits become:

- `lenient` + `balanced` → `suspicious`
- `strict` → `malicious`

There is no path today where the three modes each produce a different word for one engine set. The useful demo is **Strict escalates**, Lenient/Balanced stay cautious.

## Quick compare (running API on :8001)

```bash
./scripts/compare_sensitivity.sh
# or
PYTHONPATH=. python scripts/compare_sensitivity.py
```

UI: http://127.0.0.1:8001/ui/ — pick the same file, flip Sensitivity, Scan again (cache is keyed by sensitivity).

## Notes

- Samples are synthetic / EICAR / crafted stubs — not live malware.
- Turn **remote hash intel off** for a faster local-only demo.
- `soft_photo.png.exe` is a tiny PE renamed as `*.png.exe` so precheck flags disguise policy.

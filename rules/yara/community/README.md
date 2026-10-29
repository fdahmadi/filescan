# Community YARA rules

Place selected third-party `.yar` / `.yara` files here. The FileScan YARA engine loads them recursively with first-party rules. Broken files are skipped at compile time so one bad rule does not disable the whole engine.

## Important

- Review **license** and **false-positive** risk before enabling a pack in production.
- Prefer curated subsets over dumping an entire forge into this folder.
- Rules compile at API startup; restart `api` after adding files.

## Fetch curated sample pack

```bash
./scripts/fetch_community_yara.sh
```

Downloads a **small** Neo23x0 `signature-base` subset (Empire / scripts / webshells / suspicious strings).  
License: https://github.com/Neo23x0/signature-base/blob/master/LICENSE

Optional single extra file:

```bash
FILESCAN_COMMUNITY_YARA_URL='https://raw.githubusercontent.com/.../rule.yar' \
  ./scripts/fetch_community_yara.sh
```

## Suggested free sources (manual)

- [YARA-Forge](https://github.com/YARAHQ/yara-forge) — packaged community rules  
- [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) — check license / usage terms  

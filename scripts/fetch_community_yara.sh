#!/usr/bin/env bash
# Opt-in helper: fetch a small curated set of public Neo23x0 YARA rules.
# Review licenses before using in production.
# Broken / include-heavy files are skipped by the YARA engine at compile time.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${ROOT}/rules/yara/community"
BASE="${FILESCAN_COMMUNITY_YARA_BASE:-https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara}"
mkdir -p "${DEST}"

echo "Fetching curated community YARA rules into ${DEST}"
echo "License reference: https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

# Curated self-contained samples (no include). Keep the list short to limit FP risk.
FILES=(
  gen_powershell_empire.yar
  gen_mal_scripts.yar
  gen_webshells.yar
  gen_suspicious_strings.yar
)

ok=0
fail=0
TMP="$(mktemp -d)"
cleanup() { rm -rf "${TMP}"; }
trap cleanup EXIT

for name in "${FILES[@]}"; do
  url="${BASE}/${name}"
  out="${DEST}/${name}"
  if curl -fsSL --max-time 45 "${url}" -o "${TMP}/${name}"; then
    if grep -qE '^[[:space:]]*rule[[:space:]]+' "${TMP}/${name}"; then
      cp "${TMP}/${name}" "${out}"
      echo "  OK  ${name}"
      ok=$((ok + 1))
    else
      echo "  SKIP ${name} (not YARA-like)"
      fail=$((fail + 1))
    fi
  else
    echo "  FAIL ${name} (download)"
    fail=$((fail + 1))
  fi
done

# Optional extra URL override (single file)
if [[ -n "${FILESCAN_COMMUNITY_YARA_URL:-}" ]]; then
  extra_name="$(basename "${FILESCAN_COMMUNITY_YARA_URL}")"
  if curl -fsSL --max-time 45 "${FILESCAN_COMMUNITY_YARA_URL}" -o "${TMP}/${extra_name}"; then
    if grep -qE '^[[:space:]]*rule[[:space:]]+' "${TMP}/${extra_name}"; then
      cp "${TMP}/${extra_name}" "${DEST}/${extra_name}"
      echo "  OK  ${extra_name} (extra URL)"
      ok=$((ok + 1))
    fi
  fi
fi

echo "Done: ${ok} saved, ${fail} failed/skipped."
echo "Restart the API so YARA recompiles (docker compose up -d --force-recreate api)."
[[ "${ok}" -gt 0 ]]

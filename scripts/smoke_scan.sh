#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8001}"
API_KEY="${API_KEY:-dev-demo-key}"

echo "== health =="
curl -sS "${BASE_URL}/v1/health" | python3 -m json.tool

EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
TMP="$(mktemp /tmp/eicar.XXXXXX.txt)"
printf '%s' "$EICAR" > "$TMP"

echo "== scan EICAR test file =="
curl -sS -H "X-API-Key: ${API_KEY}" -F "file=@${TMP};filename=eicar.txt" \
  "${BASE_URL}/v1/scan" | python3 -m json.tool

rm -f "$TMP"
echo "done"

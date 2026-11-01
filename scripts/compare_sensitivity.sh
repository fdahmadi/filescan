#!/usr/bin/env bash
# Compare lenient / balanced / strict on testdata/sensitivity_demo via the live API.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$ROOT/scripts/compare_sensitivity.py" "$@"

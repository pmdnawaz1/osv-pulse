#!/usr/bin/env bash
# Regenerate example-projects/findings.csv, findings.json and findings/*.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -z "${OSV_SCANNER_BIN:-}" ] && [ -x "$ROOT/bin/osv-scanner" ]; then
  export OSV_SCANNER_BIN="$ROOT/bin/osv-scanner"
fi

if [ -z "${OSV_SCANNER_BIN:-}" ]; then
  echo "osv-scanner not found. Run 'make install-scanner' first." >&2
  exit 1
fi

export PYTHONPATH="$ROOT/runner${PYTHONPATH:+:$PYTHONPATH}"
python3 scripts/generate-example-findings.py

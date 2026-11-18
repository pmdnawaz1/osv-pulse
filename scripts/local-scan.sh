#!/usr/bin/env bash
# Run the same scan logic the GitHub runner uses, but on your own machine.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
else
  PYTHON="python3"
fi

if [ -z "${OSV_SCANNER_BIN:-}" ] && [ -x "$ROOT/bin/osv-scanner" ]; then
  export OSV_SCANNER_BIN="$ROOT/bin/osv-scanner"
fi

if [ -z "${OSV_SCANNER_BIN:-}" ]; then
  echo "osv-scanner not found. Run 'make install-scanner' first." >&2
  exit 1
fi

export PYTHONPATH="$ROOT/runner${PYTHONPATH:+:$PYTHONPATH}"
exec "$PYTHON" -m osv_pulse.local "$@"

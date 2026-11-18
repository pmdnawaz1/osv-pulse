#!/usr/bin/env bash
# Prepare this checkout for local development. Safe to run more than once.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -f worker/.dev.vars ]; then
  cp worker/.dev.vars.example worker/.dev.vars
  echo "Created worker/.dev.vars (edit it with your own values)."
else
  echo "worker/.dev.vars already exists, leaving it alone."
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r runner/requirements.txt
echo "Installed runner Python dependencies into .venv."

echo
echo "Next steps:"
echo "  1. Edit worker/.dev.vars"
echo "  2. make install-scanner    # downloads osv-scanner into ./bin"
echo "  3. make worker-deps        # installs the Worker's npm packages"
echo "  4. make test               # runs both test suites"

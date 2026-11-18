#!/usr/bin/env bash
# Send a signed test webhook to a local or deployed Worker URL.
#
# Usage:
#   GITHUB_WEBHOOK_SECRET=local-development-secret \
#     scripts/send-test-webhook.sh [url] [payload-file] [event-type]
#
# Defaults:
#   url           http://127.0.0.1:8787
#   payload-file  examples/pr-opened.json
#   event-type    pull_request
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
URL="${1:-http://127.0.0.1:8787}"
PAYLOAD_FILE="${2:-$ROOT/examples/pr-opened.json}"
EVENT="${3:-pull_request}"

if [ -z "${GITHUB_WEBHOOK_SECRET:-}" ] && [ -f "$ROOT/worker/.dev.vars" ]; then
  GITHUB_WEBHOOK_SECRET="$(grep -E '^GITHUB_WEBHOOK_SECRET=' "$ROOT/worker/.dev.vars" | head -n1 | cut -d= -f2- || true)"
  export GITHUB_WEBHOOK_SECRET
fi

if [ -z "${GITHUB_WEBHOOK_SECRET:-}" ]; then
  echo "Set GITHUB_WEBHOOK_SECRET or create worker/.dev.vars first." >&2
  exit 1
fi

SIGNATURE="$(python3 - "$PAYLOAD_FILE" <<'PY'
import hashlib, hmac, os, sys
secret = os.environ["GITHUB_WEBHOOK_SECRET"].encode()
body = open(sys.argv[1], "rb").read()
print("sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest())
PY
)"

echo "POST $URL  event=$EVENT  payload=$PAYLOAD_FILE"
curl -sS -i -X POST "$URL" \
  -H 'content-type: application/json' \
  -H "x-github-event: $EVENT" \
  -H 'x-github-delivery: test-delivery-0001' \
  -H "x-hub-signature-256: $SIGNATURE" \
  --data-binary "@$PAYLOAD_FILE"
echo

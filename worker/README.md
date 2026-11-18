# Worker

A small [Cloudflare Worker](https://developers.cloudflare.com/workers/) that receives GitHub webhooks and starts a scan job in one runner repository.

It does three things:

1. Checks the `x-hub-signature-256` header against the raw request body.
2. Decides whether the event needs a scan (new/updated/merged pull request, or push).
3. Sends a `repository_dispatch` event to the runner repository with the repository name, commit SHA, and trigger type.

It does not read the target repository and does not store anything.

## Files

| File | Purpose |
| --- | --- |
| `src/index.ts` | Request handling |
| `src/lib/signature.ts` | HMAC verification |
| `src/lib/events.ts` | Turns a webhook into a scan request |
| `src/lib/dispatch.ts` | Calls the GitHub API |
| `wrangler.toml` | Cloudflare settings |
| `.dev.vars.example` | Template for local secrets |

## Configuration

Secrets (set with `wrangler secret put NAME`):

| Name | Meaning |
| --- | --- |
| `GITHUB_WEBHOOK_SECRET` | The secret configured on the GitHub App |
| `RUNNER_PAT` | Fine-grained token with write access to the runner repository |
| `RUNNER_OWNER` | Organization or user that owns the runner repository |
| `RUNNER_REPO` | Runner repository name |

One non-secret variable lives in `wrangler.toml`: `DISPATCH_EVENT_TYPE` (default `osv-pulse-scan`). The runner workflow listens for this value.

## Local development

```bash
npm install
cp .dev.vars.example .dev.vars   # edit values
npm run dev
```

Then, from the repository root:

```bash
GITHUB_WEBHOOK_SECRET=local-development-secret \
  scripts/send-test-webhook.sh http://127.0.0.1:8787
```

`GET /health` returns a small JSON response. Any other GET returns `405`.

## Checks and tests

```bash
npm run typecheck
npm test
```

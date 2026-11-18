# osv-pulse

**Check your dependencies for known vulnerabilities on every pull request — without adding a workflow file to every repository.**

`osv-pulse` is one GitHub App plus one small Cloudflare Worker and one private GitHub Actions repository. Install the app on your organization and every repository gets dependency checks on pull requests. There is nothing to copy into each project, and no server to keep running.

The actual scanning is done by [Google's OSV-Scanner](https://github.com/google/osv-scanner).

---

## What you get

- **One install, every repository.** Install the GitHub App once. New repositories are covered automatically.
- **Checks where you already work.** Results appear as a GitHub check on the pull request, with comments on the exact line of the lockfile when OSV-Scanner can provide one.
- **No noise about old problems.** By default a pull request only fails if it introduces a vulnerability that was not there before.
- **Rules per repository.** Add an optional `.osv-pulse.yml` to change triggers, set a severity level, or ignore a specific advisory for a limited time.
- **Nothing runs from your project.** Only dependency files are read. No install scripts, no build steps, no code from the repository is executed.
- **Very low running cost.** The Worker has no server to manage and the scan job only runs when something happens.

---

## How it works

```
  Pull request / push / merge
             |
             v
     +-------------------+
     | Cloudflare Worker |   Checks the webhook signature and
     |  (this repo,      |   forwards the important details to
     |   worker/)        |   one runner repository.
     +---------+---------+
               |
               |  repository_dispatch
               v
     +-------------------+
     | Private runner    |   Checks out the commit, reads
     | repository        |   .osv-pulse.yml, runs OSV-Scanner,
     | (runner/)         |   and publishes a check.
     +---------+---------+
               |
               |  GitHub Checks API
               v
     +-------------------+
     |   Pull request    |   Pass / fail check, summary table,
     |   check + lines   |   and inline annotations.
     +-------------------+
```

In more detail:

1. GitHub sends a webhook when a pull request is opened or updated, when it is merged, or when code is pushed.
2. The Worker checks the signature using your webhook secret. If it does not match, the request is rejected. It then sends a small JSON message to the runner repository.
3. The runner job creates a GitHub token that only works for that one repository, checks out the commit, and reads its `.osv-pulse.yml` if there is one.
4. For pull requests, the job also checks out the base commit and compares the two scans. Findings that already existed on the base commit are not counted.
5. The job publishes a check with a summary table and up to 50 line annotations.

---

## Set it up

This takes about five to ten minutes.

### 1. Create the runner repository

1. Make a **private** repository in your organization called `osv-pulse-runner`.
2. Copy these files from this repo into it, keeping the same paths:
   - `runner/.github/workflows/runner.yml`
   - `runner/osv_pulse/` (the whole folder)
   - `runner/requirements.txt`
3. In that repository, add two Actions secrets:
   - `OSV_PULSE_APP_ID` — the GitHub App ID from step 3.
   - `OSV_PULSE_PRIVATE_KEY` — the App's private key (the contents of the `.pem` file).

Keep the runner repository private. Its logs contain repository names and scan results.

### 2. Create the GitHub App

1. Go to **Settings → Developer settings → GitHub Apps → New GitHub App**.
2. Set the **Webhook URL** to your Worker URL. You can put a placeholder here and change it after step 3. For local testing, [smee.io](https://smee.io) works well.
3. Create a **Webhook secret** and save it somewhere safe. You will need it twice.
4. Give the App these repository permissions:

   | Permission | Access | Why |
   | --- | --- | --- |
   | Contents | Read-only | Check out the code and dependency files |
   | Checks | Read & write | Publish the result on the pull request |
   | Pull requests | Read-only | Read pull request details from the webhook |

5. Subscribe to these events: **Pull request** and **Push**.
6. Generate a **Private key** and save the `.pem` file. Put its contents in `OSV_PULSE_PRIVATE_KEY` above.
7. Install the App on your organization. Choose **All repositories** if you want every repository covered.

### 3. Create a token for the runner repository

Create a fine-grained personal access token with **Contents: Read and Write** for `osv-pulse-runner` only. The Worker uses it to start the runner job. It does not need access to any other repository.

### 4. Deploy the Worker

```bash
git clone https://github.com/YOUR-ORG/osv-pulse.git
cd osv-pulse/worker
npm install
npx wrangler login
```

Set the four secrets:

```bash
npx wrangler secret put GITHUB_WEBHOOK_SECRET   # same secret as the App
npx wrangler secret put RUNNER_OWNER            # your org or username
npx wrangler secret put RUNNER_REPO             # osv-pulse-runner
npx wrangler secret put RUNNER_PAT              # the token from step 3
```

Then deploy:

```bash
npx wrangler deploy
```

Copy the URL it prints (for example `https://osv-pulse.example.workers.dev`) and set it as the Webhook URL on the GitHub App.

### 5. Try it

Open a pull request in a repository where the App is installed. You should see a check named `osv-pulse` within a minute or two.

You can also send a test webhook by hand:

```bash
GITHUB_WEBHOOK_SECRET=your-secret \
  scripts/send-test-webhook.sh https://osv-pulse.example.workers.dev
```

The sample payload in `examples/pr-opened.json` uses fake commit SHAs, so the runner will not be able to check it out. It is useful for checking that the Worker accepts the signature and forwards the event.

---

## Configuration

Configuration is optional. Without a config file the defaults are:

| Setting | Default |
| --- | --- |
| Pull requests (`opened`, `synchronize`, `reopened`) | On, new findings only |
| Merged pull requests | On, full repository scan |
| Direct pushes | Off |
| Severity that fails a check | `HIGH` and above |
| Block merging | Yes |

To change this, add `.osv-pulse.yml` to the root of a repository. Start by copying [`osv-pulse.example.yml`](osv-pulse.example.yml).

```yaml
version: 1

on:
  pull_request:
    enabled: true
    diff_only: true        # only count vulnerabilities added by this PR
  merge:
    enabled: true
  push:
    enabled: false
    branches: [main]       # empty list means every branch

policy:
  fail_on_severity: HIGH   # LOW | MEDIUM | HIGH | CRITICAL | NONE
  block_merge: true        # false = report but never fail the check
  ignore_cves:
    - id: GHSA-xxxx-xxxx-xxxx
      reason: "Not used by our runtime; upgrade planned for Q4"
      expires: "2026-12-31"
    - CVE-2024-12345       # short form

scan:
  paths: ["."]
  exclude_paths: ["test/**", "examples/**"]
```

### A few things worth knowing

- **New vs. all findings.** With `diff_only: true`, the runner scans the pull request commit and the base commit, then reports only findings that are not in the base scan. Set it to `false` if you want to see everything.
- **Severity levels.** A finding blocks the check when its severity is at or above `fail_on_severity`. Use `NONE` to report findings without ever blocking. If a vulnerability has no usable severity label, it is treated as blocking so it is not missed.
- **Warnings only.** `block_merge: false` publishes a `neutral` check instead of a failing one. The summary still lists everything that was found.
- **Ignored advisories.** `ignore_cves` matches the advisory ID and all of its aliases, so you can list a `CVE-...` even if OSV reports it as a `GHSA-...`. An `expires` date is a safety net: after that date the ignore stops working. Dates use `YYYY-MM-DD`.
- **Paths and excludes.** `scan.paths` accepts files or directories. Directories are searched recursively. `exclude_paths` entries are passed to OSV-Scanner as glob patterns; `test/**` also matches nested `test` directories.
- **Line annotations.** GitHub receives at most 50 annotations per check. The summary always lists every finding.

There is a [JSON Schema](osv-pulse.schema.json) for editors. Add this to the top of a local copy if you want autocomplete:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/YOUR-ORG/osv-pulse/main/osv-pulse.schema.json
```

---

## Run it locally

Everything can be run on your own machine without GitHub.

```bash
make setup              # .dev.vars, Python virtual environment, PyYAML
make install-scanner    # pinned osv-scanner binary in ./bin
make worker-deps        # npm packages for the Worker
make test               # all tests
```

### Scan a repository

```bash
make local-scan ARGS="--repo /path/to/a/repo"
```

Useful options:

```bash
# Report only what a pull request would add
make local-scan ARGS="--repo . --diff-against ../main-checkout"

# Machine-readable output for other tools
make local-scan ARGS="--repo . --format json --output report.json"

# Try a config file without scanning
make local-scan ARGS="--repo . --config ./my-rules.yml --check-config"

# Report but do not fail
make local-scan ARGS="--repo . --warn-only"
# or
make local-scan ARGS="--repo . --fail-on CRITICAL"
```

Exit codes: `0` = no blocking findings, `1` = blocking findings, `2` = the scan could not run.

The local command uses the repository's own `.osv-pulse.yml`. `--config` replaces it, and `--fail-on` / `--warn-only` change the policy for that run only.

### Run the Worker locally

```bash
cp worker/.dev.vars.example worker/.dev.vars   # then edit the values
make worker-dev
```

In a second terminal:

```bash
GITHUB_WEBHOOK_SECRET=local-development-secret \
  scripts/send-test-webhook.sh http://127.0.0.1:8787
```

The Worker only forwards valid signatures. If you see `invalid_signature`, check that the secret in `.dev.vars` matches the one used by `send-test-webhook.sh`.

### Send a webhook from GitHub during development

[smee.io](https://smee.io) gives you a public URL that forwards requests to your machine:

```bash
npx smee -u https://smee.io/YOUR-CHANNEL -t http://127.0.0.1:8787
```

Use the smee URL as the App's webhook URL while developing.

---

## Commands

Run `make help` to see this list in your terminal.

| Command | What it does |
| --- | --- |
| `make setup` | Create local config files and a Python environment |
| `make install-scanner` | Download and verify a pinned OSV-Scanner binary |
| `make worker-deps` | Install Worker npm packages |
| `make worker-dev` | Start the Worker locally |
| `make worker-test` | Run Worker tests |
| `make runner-test` | Run runner tests |
| `make test` | Run all tests |
| `make check` | Type-check and run all tests |
| `make local-scan ARGS="..."` | Run a scan on this machine |
| `make send-test-webhook` | Send a signed sample webhook |
| `make deploy` | Deploy the Worker with Wrangler |

---

## Security notes

- The Worker checks every webhook signature before doing anything else.
- The token used by the runner is created for a single repository and expires when the job finishes.
- The runner never installs or builds code from the repository it scans. OSV-Scanner only reads lockfiles and manifests.
- The OSV-Scanner binary is downloaded from the official release and checked against the published SHA-256 checksum.
- Keep the runner repository private so scan summaries are not visible outside your organization.
- The fine-grained token for `repository_dispatch` only needs write access to the runner repository. Do not give it organization-wide access.

---

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `invalid_signature` from the Worker | The webhook secret in the App and in `GITHUB_WEBHOOK_SECRET` differ. Re-sign with `scripts/send-test-webhook.sh` to confirm. |
| Webhook times out or never arrives | Check the App's Webhook URL and recent deliveries in GitHub App settings. |
| No check appears on the PR | Confirm the App is installed on that repository and that both `Pull request` and `Push` events are subscribed. Check the runner job in Actions. |
| Check says "Scan skipped by configuration" | That trigger is disabled in the repository's `.osv-pulse.yml` (or the default for pushes). |
| Runner fails at token creation | `OSV_PULSE_APP_ID` or `OSV_PULSE_PRIVATE_KEY` is missing or wrong in the runner repository. |
| Runner says "missing or invalid headSha" | The webhook was not from GitHub, or it was edited. Re-install the App and let GitHub send a fresh event. |
| `dispatch_failed` in Worker logs | The `RUNNER_PAT` cannot write to the runner repository, or `RUNNER_OWNER` / `RUNNER_REPO` are wrong. |
| "No dependency files were found" | The repo has no supported lockfile in the scanned paths, or `scan.paths` points somewhere else. |
| Findings show as `UNKNOWN` severity | The advisory has no severity label we can read. They block by default; set `fail_on_severity: NONE` to change that. |

`npx wrangler tail` shows Worker requests. The runner's Actions log prints the scan command output and the full summary.

---

## Project layout

```
worker/                  Cloudflare Worker (signature check + dispatch)
  src/                   Source files
  test/                  Unit tests
runner/                  Files to copy into the private runner repository
  .github/workflows/     The Actions workflow
  osv_pulse/             Config parsing, scanning, checks, local CLI
  tests/                 Unit tests
scripts/                 Local helper scripts
examples/                Sample webhook payloads
osv-pulse.example.yml    Config file to copy into a repository
osv-pulse.schema.json    Editor autocomplete schema
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and small pull requests are welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).

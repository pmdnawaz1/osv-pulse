# Contributing

Thanks for helping out. This document covers the practical details.

## Getting set up

```bash
git clone https://github.com/YOUR-ORG/osv-pulse.git
cd osv-pulse
make setup
make worker-deps
make install-scanner
make test
```

You need Python 3.10+, Node 20+, and `curl`. `make setup` creates a `.venv` and installs PyYAML.

## Before opening a pull request

```bash
make check
```

That runs the TypeScript type checker and both test suites. If you changed the Worker, add a test in `worker/test/`. If you changed config parsing, scanning, or check output, add a test in `runner/tests/`.

## Style

- Plain names and short comments. Avoid internal slang in code and docs.
- TypeScript in `worker/src/`, Python in `runner/osv_pulse/`.
- Python code targets 3.10+ and uses the standard library where practical. PyYAML is the only runtime dependency.
- Keep the Worker stateless. It should never read a target repository or keep state between requests.
- Keep the runner's inputs in environment variables so the CLI and the Actions job share the same code path.

## Trying a change end to end

```bash
make worker-dev
```

In another terminal:

```bash
GITHUB_WEBHOOK_SECRET=local-development-secret \
  scripts/send-test-webhook.sh http://127.0.0.1:8787
```

For the runner, use the local CLI against a test repository:

```bash
make local-scan ARGS="--repo /path/to/test-repo --format json"
```

## Reporting a problem

Include the trigger (pull request, merge, or push), the Worker response if you have it, and the runner job log with secrets removed. A sample `.osv-pulse.yml` helps too.

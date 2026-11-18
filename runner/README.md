# Runner

Copy this folder into a private repository called `osv-pulse-runner`:

```
runner/.github/workflows/runner.yml   -> osv-pulse-runner/.github/workflows/runner.yml
runner/osv_pulse/                     -> osv-pulse-runner/osv_pulse/
runner/requirements.txt               -> osv-pulse-runner/requirements.txt
```

The workflow listens for `repository_dispatch` events of type `osv-pulse-scan`. The Worker sends those events.

## Required secrets

Set these in the runner repository's **Settings → Secrets and variables → Actions**:

| Name | Where it comes from |
| --- | --- |
| `OSV_PULSE_APP_ID` | GitHub App ID |
| `OSV_PULSE_PRIVATE_KEY` | GitHub App private key (the `.pem` file contents) |

The workflow uses `actions/create-github-app-token` to create a token that only works for the repository being scanned. That token is used for checkout, for publishing the check, and for the pull request comment. The GitHub App must have **Issues: Read & write** for the comment; if it does not, the runner logs a warning and continues.

## What the workflow does

1. Reads the request JSON sent by the Worker. Commit SHAs are checked to be hexadecimal before use.
2. Creates a short-lived token for the target repository.
3. Checks out the pull request commit. For pull requests it also checks out the base commit into `target-base` so findings can be compared.
4. Downloads OSV-Scanner and verifies its checksum.
5. Installs PyYAML and runs `python3 osv_pulse/main.py`.
6. Uploads the scan files as an artifact for debugging.

## Environment variables used by `main.py`

| Name | Meaning | Default |
| --- | --- | --- |
| `OSV_PULSE_PAYLOAD` | The request JSON, as a string | required |
| `OSV_PULSE_PAYLOAD_FILE` | Read the request JSON from this file instead | unset |
| `OSV_PULSE_TOKEN` | Token used to publish the check | unset (prints to stdout) |
| `OSV_PULSE_TARGET_DIR` | Checkout to scan | `.` |
| `OSV_PULSE_BASE_DIR` | Base checkout for comparison | unset |
| `OSV_PULSE_WORKDIR` | Where result files are written | `.osv-pulse-work` |
| `OSV_SCANNER_BIN` | Path to `osv-scanner` | `osv-scanner` |

## Running the CLI without GitHub

From the repository root:

```bash
make install-scanner
make local-scan ARGS="--repo ./some-project --format json"
```

See the root [README](../README.md#run-it-locally) for more examples. The CLI lives in `osv_pulse/local.py`

## Tests

```bash
PYTHONPATH=runner python3 -m unittest discover -s runner/tests -v
```

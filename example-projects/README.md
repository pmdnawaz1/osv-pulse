# Example projects

Small dependency-only projects used to demonstrate osv-pulse and to check that the
scanner is producing the output we expect. They contain lockfiles and manifests, but
no application code — OSV-Scanner only needs the dependency files.

Every version pinned here was chosen because OSV actually reports an advisory for it
(or, for the control project, because OSV reports none at the time of generation).
The reports in this folder are generated from real scan output; none of the findings,
severities, or fixed versions were written by hand.

## Fixtures

| Project | What it shows |
| --- | --- |
| [`npm-legacy-lockfile`](npm-legacy-lockfile/) | A package-lock with `lodash@4.17.15` and a clean control dependency |
| [`python-requirements`](python-requirements/) | A `requirements.txt` pin, plus transitive packages OSV-Scanner resolves |
| [`go-module`](go-module/) | A `go.mod` with a vulnerable module version |
| [`npm-monorepo`](npm-monorepo/) | Two workspaces and `scan.paths` in `.osv-pulse.yml` |
| [`clean-project`](clean-project/) | A project with no findings (the passing case) |
| [`diff-demo`](diff-demo/) | A base and head checkout showing `diff_only: true` |

## Generated reports

| File | Contents |
| --- | --- |
| [`findings.csv`](findings.csv) | One row per finding, ready for spreadsheets or scripts |
| [`findings.json`](findings.json) | Full scan reports, including config and counts |
| [`findings/`](findings/) | One Markdown document per advisory, plus an index |

Each finding document lists the advisory, the severity and fixed version reported by
OSV, the fixtures where it was found, and the command used to reproduce the scan.

## Regenerate

```bash
make example-findings
```

The script runs `scripts/local-scan.sh` for every fixture, then writes the CSV, JSON,
and Markdown docs. It records the OSV-Scanner version and the UTC generation time in
the output so you can tell how fresh the data is.

## Truth notes

- Advisory data comes from OSV at scan time. It changes as advisories are updated, so
  regenerate the reports before relying on the counts.
- "Fixed version" is the version OSV reports as the first fixed release, not a promise
  that upgrading fixes every issue in your application.
- Severity is what the advisory reports. These documents make no claim about whether
  a vulnerability is reachable or exploitable in any of the fixtures.
- These lockfiles pin vulnerable versions on purpose. Do not copy them into production.

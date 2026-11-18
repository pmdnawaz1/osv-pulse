# npm lockfile with known vulnerabilities

A minimal npm project with two pinned dependencies:

| Package | Version | Why it is here |
| --- | --- | --- |
| `lodash` | `4.17.15` | Has published advisories in OSV, including `CVE-2020-8203` |
| `is-number` | `7.0.0` | Used as a control: no published advisories at scan time |

There is no application code. OSV-Scanner only reads the lockfile.

## Reproduce

```bash
bash scripts/local-scan.sh --repo example-projects/npm-legacy-lockfile \
  --format json
```

Generated results live in `example-projects/findings.csv` and `example-projects/findings/`.

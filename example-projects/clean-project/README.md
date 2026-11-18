# Clean project

Pins `is-number@7.0.0`, which had no published advisories in OSV at the time the
sample data was generated. A scan of this project produces an empty findings list
and exit code `0`.

This is a control fixture. It exists to show what a passing scan looks like.

## Reproduce

```bash
bash scripts/local-scan.sh --repo example-projects/clean-project \
  --format json
```

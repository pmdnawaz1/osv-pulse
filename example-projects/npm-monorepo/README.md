# Monorepo with two lockfiles

Shows how `.osv-pulse.yml` limits scanning to specific directories.

- `frontend/package-lock.json` pins `dompurify@3.4.11`
- `backend/package-lock.json` pins `lodash@4.17.15`

Both versions have published advisories in OSV. The config sets `scan.paths` to just
these two workspaces.

## Reproduce

```bash
bash scripts/local-scan.sh --repo example-projects/npm-monorepo \
  --format json
```

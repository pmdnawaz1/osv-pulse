# Go module

Pins `github.com/jackc/pgx/v5 v5.5.5`, which has published advisories in OSV
(for example `CVE-2026-33815`). No Go source code is needed: OSV-Scanner reads `go.mod`.

## Reproduce

```bash
bash scripts/local-scan.sh --repo example-projects/go-module \
  --format json
```

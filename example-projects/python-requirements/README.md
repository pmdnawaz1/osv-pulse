# Python requirements file

Pins `anyio==4.9.0`, which has published advisories in OSV.

OSV-Scanner also resolves transitive dependencies for Python manifests. In the generated
results you will see findings for `idna` as well, even though it is not written in
`requirements.txt`. That comes from OSV-Scanner, not from osv-pulse.

## Reproduce

```bash
bash scripts/local-scan.sh --repo example-projects/python-requirements \
  --format json
```

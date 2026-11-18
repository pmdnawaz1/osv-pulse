# Pull request diff demo

Shows how `diff_only: true` works.

- `base/` is the branch the pull request started from. It has only `is-number@7.0.0`.
- `head/` is the pull request branch. It adds `lodash@4.17.15`, which has published advisories.

Both files are scanned. Findings present in `base/` are removed from the result, so the
reported findings are only the ones introduced by the change. `head/.osv-pulse.yml`
enables `diff_only` explicitly.

## Reproduce

```bash
bash scripts/local-scan.sh \
  --repo example-projects/diff-demo/head \
  --diff-against example-projects/diff-demo/base \
  --format json
```

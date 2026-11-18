# Policy templates

Copy one of these to the root of a repository as `.osv-pulse.yml`.

| Template | What it does |
| --- | --- |
| [`.osv-pulse.block-critical.yml`](.osv-pulse.block-critical.yml) | Blocks only on `CRITICAL` findings |
| [`.osv-pulse.block-high.yml`](.osv-pulse.block-high.yml) | Blocks on `HIGH` and `CRITICAL` (the default) |
| [`.osv-pulse.warn-only.yml`](.osv-pulse.warn-only.yml) | Reports every severity but never blocks |

## When does a pull request get blocked?

All of these must be true:

1. The trigger is enabled (`on.pull_request.enabled: true`).
2. The finding is counted. With `diff_only: true`, findings that already exist on the
   base commit are ignored. `policy.ignore_cves` also removes matching advisories.
3. The finding is at or above `policy.fail_on_severity`. Findings with no severity
   label are treated as blocking.
4. `policy.block_merge: true`.
5. Your branch protection rule requires the `osv-pulse` check to pass.

If step 5 is not set, the check can fail but GitHub will still allow the merge. A
`neutral` conclusion (from `block_merge: false`) does not block.

## Changing the rule

Edit `policy.fail_on_severity`. Allowed values are `LOW`, `MEDIUM`, `HIGH`,
`CRITICAL`, and `NONE`. `NONE` reports findings but never blocks, like
`block_merge: false`.

To let a specific advisory through for a limited time, add it to `ignore_cves`:

```yaml
policy:
  ignore_cves:
    - id: GHSA-xxxx-xxxx-xxxx
      reason: "Upgrading is scheduled for next sprint"
      expires: "2026-12-31"
```

After `expires` the ignore stops applying. The ID may be any alias of the advisory,
including a `CVE-...` number.

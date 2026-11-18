# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Email the maintainers privately with:

- what you found and what an attacker could do,
- the version or commit you tested,
- steps to reproduce, if you can share them.

You should get a reply within a few days.

## What is in scope

- Signature checking in the Cloudflare Worker
- Token handling in the runner repository
- Any path where code from a scanned repository could be executed
- The checksum check when downloading OSV-Scanner

## What is out of scope

- Vulnerabilities in dependencies reported by OSV-Scanner (report those to the package maintainers)
- GitHub or Cloudflare service issues
- Self-hosted runner configuration outside this project

## Design notes

The Worker only accepts requests with a valid GitHub HMAC signature. The runner creates a token for one repository per job and never checks out the runner repository with credentials from the target. Repository code is only read as files; no install or build scripts are run.

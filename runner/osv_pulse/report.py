"""CSV report shared by the local CLI and the GitHub runner."""

from __future__ import annotations

import csv
import io
from pathlib import Path

CSV_COLUMNS = (
    "repository",
    "mode",
    "file",
    "package",
    "version",
    "ecosystem",
    "advisory",
    "aliases",
    "severity",
    "cvss",
    "fixed_version",
    "blocking",
    "summary",
    "url",
)


def render_csv(findings, blocking_ids: set[str], repo: Path | str, mode: str) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for finding in findings:
        canonical = finding.canonical
        writer.writerow(
            {
                "repository": str(repo),
                "mode": mode,
                "file": finding.path,
                "package": finding.package,
                "version": finding.version,
                "ecosystem": finding.ecosystem,
                "advisory": canonical,
                "aliases": ";".join(sorted(finding.all_ids - {canonical})),
                "severity": finding.severity,
                "cvss": "" if finding.cvss is None else finding.cvss,
                "fixed_version": finding.fixed_version or "",
                "blocking": "yes" if canonical in blocking_ids else "no",
                "summary": finding.summary,
                "url": f"https://osv.dev/vulnerability/{canonical}",
            }
        )
    return buffer.getvalue()

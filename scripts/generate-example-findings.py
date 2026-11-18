#!/usr/bin/env python3
"""Scan the example fixtures and write the generated findings reports."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "runner"))

from osv_pulse.report import CSV_COLUMNS  # noqa: E402

PROJECTS: dict[str, tuple[str, list[str]]] = {
    "npm-legacy-lockfile": ("example-projects/npm-legacy-lockfile", []),
    "python-requirements": ("example-projects/python-requirements", []),
    "go-module": ("example-projects/go-module", []),
    "npm-monorepo": ("example-projects/npm-monorepo", []),
    "clean-project": ("example-projects/clean-project", []),
    "diff-demo": (
        "example-projects/diff-demo/head",
        ["--diff-against", "example-projects/diff-demo/base"],
    ),
}

FINDINGS_DIR = ROOT / "example-projects" / "findings"


def scanner_version() -> str:
    binary = __import__("os").environ.get("OSV_SCANNER_BIN", "osv-scanner")
    try:
        result = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, check=False
        )
        for line in result.stdout.splitlines():
            if line.startswith("osv-scanner version:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def scan_projects(work: Path) -> dict[str, dict]:
    reports: dict[str, dict] = {}
    for name, (label, extra) in PROJECTS.items():
        output = work / f"{name}.json"
        command = [
            "bash",
            str(ROOT / "scripts" / "local-scan.sh"),
            "--repo",
            str(ROOT / label),
            "--workdir",
            str(work / f"work-{name}"),
            "--format",
            "json",
            "--output",
            str(output),
            *extra,
        ]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1):
            raise RuntimeError(f"scan failed for {name}: {result.stderr[-2000:]}")
        reports[name] = json.loads(output.read_text(encoding="utf-8"))
        reports[name]["label"] = label
        reports[name]["reproduce"] = " ".join(
            ["bash scripts/local-scan.sh", f"--repo {label}", *extra, "--format json"]
        )
        findings = len(reports[name]["findings"])
        blocking = len(reports[name]["blocking_ids"])
        print(f"  {name:22} findings={findings:3} blocking={blocking:3}")
    return reports


def all_rows(reports: dict[str, dict]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for report in reports.values():
        blocking = set(report["blocking_ids"])
        for finding in report["findings"]:
            canonical = finding["canonical"]
            aliases = ";".join(
                sorted(value for value in finding.get("all_ids", []) if value != canonical)
            )
            rows.append(
                {
                    "repository": report["label"],
                    "mode": report["mode"],
                    "file": finding["path"],
                    "package": finding["package"],
                    "version": finding["version"],
                    "ecosystem": finding["ecosystem"],
                    "advisory": canonical,
                    "aliases": aliases,
                    "severity": finding["severity"],
                    "cvss": "" if finding.get("cvss") is None else str(finding["cvss"]),
                    "fixed_version": finding.get("fixed_version") or "",
                    "blocking": "yes" if canonical in blocking else "no",
                    "summary": finding.get("summary", ""),
                    "url": f"https://osv.dev/vulnerability/{canonical}",
                }
            )
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    rows.sort(key=lambda row: (rank.get(row["severity"], 9), row["advisory"], row["repository"]))
    return rows


def write_csv(rows: list[dict[str, str]]) -> None:
    path = ROOT / "example-projects" / "findings.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {path.relative_to(ROOT)}")


def write_json(reports: dict[str, dict], version: str, generated: str) -> None:
    path = ROOT / "example-projects" / "findings.json"
    payload = {
        "generated_at": generated,
        "scanner_version": version,
        "note": "Generated from OSV-Scanner output. Advisory data may change over time.",
        "projects": [
            {
                "project": name,
                "repository": report["label"],
                "mode": report["mode"],
                "config": report["config"],
                "warnings": report["warnings"],
                "baseline_count": report["baseline_count"],
                "ignored_count": report["ignored_count"],
                "findings": report["findings"],
            }
            for name, report in reports.items()
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)}")


def write_finding_docs(rows: list[dict[str, str]], reports: dict[str, dict], version: str, generated: str) -> None:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row["advisory"]].append(row)

    for advisory, entries in sorted(grouped.items()):
        first = entries[0]
        lines = [
            f"# {advisory} — {first['summary'] or 'advisory'}",
            "",
            "## Advisory details",
            "",
            f"- OSV: [{advisory}]({first['url']})",
            f"- Also published as: {', '.join(sorted(filter(None, first['aliases'].split(';')))) or 'none listed'}",
            f"- Severity reported by OSV: {first['severity']}",
            f"- CVSS base score: {first['cvss'] or 'not provided in the advisory'}",
            f"- Fixed version reported by OSV: {first['fixed_version'] or 'no fix listed'}",
            "",
            "## Where it appears in these fixtures",
            "",
            "| Fixture | File | Package | Version | Blocking at default HIGH gate |",
            "| --- | --- | --- | --- | --- |",
        ]
        for entry in entries:
            lines.append(
                f"| `{entry['repository']}` | `{entry['file']}` | {entry['package']} "
                f"| {entry['version']} | {entry['blocking']} |"
            )

        lines.extend(
            [
                "",
                "## How this was produced",
                "",
                f"Scanned with OSV-Scanner {version} on {generated}. Severity, fixed version, and",
                "summary come from the advisory data returned by OSV at scan time. They can change",
                "as advisories are updated. No exploitability claim is made here.",
                "",
                "Reproduce one of the scans:",
                "",
                "```bash",
                reports[next(name for name, report in reports.items() if report["label"] == entries[0]["repository"])]["reproduce"],
                "```",
                "",
                "The fixtures pin outdated versions on purpose. Do not copy them into production.",
                "",
            ]
        )
        path = FINDINGS_DIR / f"{advisory}.md"
        path.write_text("\n".join(lines), encoding="utf-8")

    index = [
        "# Findings index",
        "",
        f"Generated from OSV-Scanner {version} on {generated}.",
        "",
        f"{len(grouped)} distinct advisories across {len(rows)} findings.",
        "",
        "| Advisory | Severity | Package | Fixtures |",
        "| --- | --- | --- | --- |",
    ]
    for advisory, entries in sorted(grouped.items()):
        fixtures = ", ".join(sorted({row["repository"] for row in entries}))
        index.append(
            f"| [{advisory}]({advisory}.md) | {entries[0]['severity']} "
            f"| {entries[0]['package']} | {fixtures} |"
        )
    index.append("")
    (FINDINGS_DIR / "README.md").write_text("\n".join(index), encoding="utf-8")
    print(f"wrote {FINDINGS_DIR.relative_to(ROOT)}/ ({len(grouped)} advisories)")


def main() -> None:
    version = scanner_version()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"OSV-Scanner {version}, generated {generated}")
    with tempfile.TemporaryDirectory(prefix="osv-pulse-examples-") as tmp:
        reports = scan_projects(Path(tmp))
    rows = all_rows(reports)
    write_csv(rows)
    write_json(reports, version, generated)
    write_finding_docs(rows, reports, version, generated)


if __name__ == "__main__":
    main()

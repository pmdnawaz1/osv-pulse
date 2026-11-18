"""Run a scan from a GitHub Actions dispatch and publish a check run.

All inputs come from environment variables so the same code can be called by the
workflow or by a local script. See runner/README.md for the full list.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .annotations import build_annotations
from .config import ConfigError, load_config
from .github_client import GitHubClient
from .models import Finding
from .scanner import Scanner


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _load_payload() -> dict[str, Any]:
    raw = _env("OSV_PULSE_PAYLOAD")
    payload_file = _env("OSV_PULSE_PAYLOAD_FILE")
    if payload_file and Path(payload_file).is_file():
        raw = Path(payload_file).read_text(encoding="utf-8")
    if not raw.strip():
        raise RuntimeError("OSV_PULSE_PAYLOAD is empty")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise RuntimeError("OSV_PULSE_PAYLOAD must be a JSON object")
    return payload


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def render_summary(
    findings: list[Finding],
    *,
    config: Any,
    mode: str,
    commit: str,
    baseline_count: int,
    ignored_count: int,
    annotations_truncated: bool,
) -> str:
    noun = "vulnerability" if len(findings) == 1 else "vulnerabilities"
    label = f"new {noun}" if mode == "pr" else noun
    lines = [
        f"## osv-pulse: {len(findings)} {label} found",
        "",
    ]

    if findings:
        lines.extend(
            [
                "| Severity | Advisory | Package | Installed | Fixed in | File |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in findings[:25]:
            fixed = finding.fixed_version or "no fix yet"
            lines.append(
                "| {severity} | [{id}](https://osv.dev/vulnerability/{id}) | {package}@{version} "
                "| {version} | {fixed} | `{path}` |".format(
                    severity=finding.severity.title(),
                    id=finding.canonical,
                    package=finding.package,
                    version=finding.version,
                    fixed=fixed,
                    path=finding.path,
                )
            )
        if len(findings) > 25:
            lines.append("", f"_...and {len(findings) - 25} more (see the job log)._")
    else:
        lines.append("No vulnerabilities found in the scanned paths.")

    lines.extend(
        [
            "",
            "### Scan details",
            "",
            f"- Commit: `{commit}`",
            f"- Trigger: `{mode}`",
            f"- Fail at: `{config.fail_on_severity}`"
            + (" (warnings only)" if not config.block_merge else ""),
            f"- Config: `{config.config_file or 'defaults (no .osv-pulse.yml)'}`",
        ]
    )
    if mode == "pr":
        lines.append(f"- Pre-existing findings not counted: {baseline_count}")
    if ignored_count:
        lines.append(f"- Findings hidden by ignore rules: {ignored_count}")
    if annotations_truncated:
        lines.append("- Only the first 50 inline annotations are shown.")
    return "\n".join(lines)


def main() -> int:
    payload = _load_payload()
    repository = payload.get("repository") or {}
    owner = str(repository.get("owner", ""))
    repo_name = str(repository.get("name", ""))
    head_sha = str(payload.get("headSha", ""))
    mode = str(payload.get("mode", ""))
    branch = str(payload.get("branch") or "")

    work_dir = Path(_env("OSV_PULSE_WORKDIR", ".osv-pulse-work")).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    target = Path(_env("OSV_PULSE_TARGET_DIR", ".")).resolve()
    base_dir_raw = _env("OSV_PULSE_BASE_DIR")
    base_dir = Path(base_dir_raw).resolve() if base_dir_raw else None

    token = _env("OSV_PULSE_TOKEN")
    client = GitHubClient(token) if token else None

    def publish(conclusion: str, title: str, summary: str, annotations: list[dict[str, Any]] | None = None) -> None:
        body: dict[str, Any] = {
            "name": "osv-pulse",
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "completed_at": _now(),
            "details_url": "https://osv.dev",
            "output": {"title": title, "summary": summary[:65000], "text": ""},
        }
        if annotations:
            body["output"]["annotations"] = annotations

        if client is None:
            print(f"[osv-pulse] {conclusion}: {title}\n{summary}", flush=True)
            return
        status, response = client.create_check_run(owner, repo_name, body)
        if status >= 400:
            print(f"[osv-pulse] could not publish check: HTTP {status} {response}", flush=True)
        else:
            print(f"[osv-pulse] published check: {conclusion}", flush=True)

    try:
        config = load_config(target)
    except ConfigError as exc:
        publish("failure", "Invalid .osv-pulse.yml", f"Fix the config file and rerun.\n\n{exc}")
        print(f"[osv-pulse] config error: {exc}", file=sys.stderr, flush=True)
        return 1

    if not config.scan_enabled_for(mode, branch):
        publish(
            "neutral",
            "Scan skipped by configuration",
            f"The `{mode}` trigger is disabled in `{config.config_file or 'defaults'}`.",
        )
        return 0

    try:
        scanner = Scanner(_env("OSV_SCANNER_BIN", "osv-scanner"), config)
        head = scanner.run(target, work_dir / "head.json")

        # SARIF carries file and line information for inline annotations.
        sarif_path = work_dir / "head.sarif"
        try:
            scanner.run(target, sarif_path, "sarif")
        except Exception as exc:  # annotations are a nice-to-have, not a scan failure
            print(f"[osv-pulse] SARIF scan skipped: {exc}", flush=True)

        findings = list(head.findings)
        baseline_count = 0
        base_raw = work_dir / "base.json"
        if mode == "pr" and config.pr_diff_only and base_dir and base_dir.is_dir():
            baseline = scanner.run(base_dir, base_raw)
            baseline_keys = {item.key for item in baseline.findings}
            before = len(findings)
            findings = [item for item in findings if item.key not in baseline_keys]
            baseline_count = before - len(findings)

        ignored_count = sum(1 for item in findings if config.is_ignored(item.all_ids))
        findings = [item for item in findings if not config.is_ignored(item.all_ids)]
        blocking = [item for item in findings if config.is_blocking(item)]

        all_ids = {value for item in findings for value in item.all_ids}
        blocking_ids = {value for item in blocking for value in item.all_ids}
        annotations, truncated = build_annotations(sarif_path, target, all_ids, blocking_ids)

        if not blocking:
            conclusion = "success"
        elif config.block_merge:
            conclusion = "failure"
        else:
            conclusion = "neutral"

        summary = render_summary(
            findings,
            config=config,
            mode=mode,
            commit=head_sha,
            baseline_count=baseline_count,
            ignored_count=ignored_count,
            annotations_truncated=truncated,
        )
        for warning in head.warnings:
            summary += f"\n> Note: {warning}"
        publish(conclusion, f"osv-pulse: {len(findings)} finding(s)", summary, annotations)
        print(summary, flush=True)
        return 0
    except Exception as exc:
        traceback.print_exc()
        # Infrastructure problems should not block a pull request.
        publish("neutral", "osv-pulse could not finish", f"Scan error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

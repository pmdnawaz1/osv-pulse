"""Command line entry point for running scans locally or in any CI system.

Examples:
    python3 -m osv_pulse.local --repo ./my-app
    python3 -m osv_pulse.local --repo . --diff-against ../baseline --format json
    python3 -m osv_pulse.local --check-config --repo .
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

import yaml

from .config import SEVERITY_LEVELS, Config, ConfigError, load_config, parse_config
from .main import render_summary
from .scanner import Scanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osv-pulse",
        description="Scan dependency files with osv-scanner and apply osv-pulse policy.",
    )
    parser.add_argument("--repo", "-r", default=".", help="Repository to scan (default: .)")
    parser.add_argument("--config", "-c", help="Use this config file instead of the repo's own")
    parser.add_argument(
        "--diff-against",
        help="Compare against another checkout and report only new findings",
    )
    parser.add_argument("--workdir", default=".osv-pulse-work", help="Where to put result files")
    parser.add_argument(
        "--scanner",
        default=os.environ.get("OSV_SCANNER_BIN", "osv-scanner"),
        help="Path to the osv-scanner binary",
    )
    parser.add_argument("--fail-on", choices=SEVERITY_LEVELS, help="Override the severity gate")
    parser.add_argument(
        "--warn-only", action="store_true", help="Never exit non-zero because of findings"
    )
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--output", "-o", help="Write output to a file instead of stdout")
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate and print the resolved config, then exit",
    )
    return parser


def load_local_config(repo: Path, config_path: str | None) -> Config:
    if not config_path:
        return load_config(repo)
    path = Path(config_path).resolve()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return parse_config(data, config_file=str(path))


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"osv-pulse: not a directory: {repo}", file=sys.stderr)
        return 2

    try:
        config = load_local_config(repo, args.config)
    except ConfigError as exc:
        print(f"osv-pulse: invalid config: {exc}", file=sys.stderr)
        return 2

    if args.fail_on:
        config.fail_on_severity = args.fail_on
    if args.warn_only:
        config.block_merge = False

    if args.check_config:
        print(json.dumps(_config_to_dict(config), indent=2))
        return 0

    workdir = Path(args.workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    try:
        scanner = Scanner(args.scanner, config)
        head = scanner.run(repo, workdir / "head.json")
        findings = list(head.findings)
        baseline_count = 0

        if args.diff_against:
            baseline_repo = Path(args.diff_against).resolve()
            if not baseline_repo.is_dir():
                print(f"osv-pulse: not a directory: {baseline_repo}", file=sys.stderr)
                return 2
            baseline = scanner.run(baseline_repo, workdir / "base.json")
            baseline_keys = {item.key for item in baseline.findings}
            before = len(findings)
            findings = [item for item in findings if item.key not in baseline_keys]
            baseline_count = before - len(findings)

        ignored_count = sum(1 for item in findings if config.is_ignored(item.all_ids))
        findings = [item for item in findings if not config.is_ignored(item.all_ids)]
        blocking = [item for item in findings if config.is_blocking(item)]

        if args.format == "json":
            output = json.dumps(
                {
                    "repo": str(repo),
                    "mode": "diff" if args.diff_against else "full",
                    "config": _config_to_dict(config),
                    "findings": [_finding_to_dict(item) for item in findings],
                    "blocking_ids": sorted({item.canonical for item in blocking}),
                    "baseline_count": baseline_count,
                    "ignored_count": ignored_count,
                    "warnings": head.warnings,
                },
                indent=2,
            )
        else:
            output = render_summary(
                findings,
                config=config,
                mode="pr" if args.diff_against else "full",
                commit="local",
                baseline_count=baseline_count,
                ignored_count=ignored_count,
                annotations_truncated=False,
            )

        if args.output:
            Path(args.output).write_text(output + "\n", encoding="utf-8")
            print(f"osv-pulse: wrote {args.output}", file=sys.stderr)
        else:
            print(output)

        if blocking and config.block_merge:
            return 1
        return 0
    except (OSError, ValueError) as exc:
        print(f"osv-pulse: scan failed: {exc}", file=sys.stderr)
        return 2


def _finding_to_dict(finding) -> dict[str, object]:
    data = asdict(finding)
    data["canonical"] = finding.canonical
    data["all_ids"] = sorted(finding.all_ids)
    return data


def _config_to_dict(config: Config) -> dict[str, object]:
    return {
        "config_file": config.config_file,
        "version": config.version,
        "pull_request": {"enabled": config.pr_enabled, "diff_only": config.pr_diff_only},
        "merge": {"enabled": config.merge_enabled},
        "push": {"enabled": config.push_enabled, "branches": config.push_branches},
        "policy": {
            "fail_on_severity": config.fail_on_severity,
            "block_merge": config.block_merge,
            "ignore_cves": [
                {
                    "id": rule.id,
                    "reason": rule.reason,
                    "expires": rule.expires.isoformat() if rule.expires else None,
                }
                for rule in config.ignores
            ],
        },
        "scan": {"paths": config.paths, "exclude_paths": config.exclude_paths},
    }


if __name__ == "__main__":
    raise SystemExit(run())

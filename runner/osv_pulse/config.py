"""Read and validate the optional .osv-pulse.yml file in a repository."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .models import SEVERITY_RANK

SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE")

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "on": {
        "pull_request": {"enabled": True, "diff_only": True, "comment": True},
        "merge": {"enabled": True},
        "push": {"enabled": False, "branches": []},
    },
    "policy": {
        "fail_on_severity": "HIGH",
        "block_merge": True,
        "ignore_cves": [],
    },
    "scan": {
        "paths": ["."],
        "exclude_paths": [],
    },
}

CONFIG_FILENAMES = (".osv-pulse.yml", ".osv-pulse.yaml")


class ConfigError(ValueError):
    """Raised when a repository's config file cannot be used."""


@dataclass(frozen=True)
class IgnoreRule:
    id: str
    reason: str = ""
    expires: date | None = None

    def is_active(self, today: date | None = None) -> bool:
        """An expired rule stops applying, so ignores cannot silently last forever."""
        if self.expires is None:
            return True
        return (today or datetime.now(timezone.utc).date()) <= self.expires


@dataclass
class Config:
    version: int = 1
    pr_enabled: bool = True
    pr_diff_only: bool = True
    pr_comment_enabled: bool = True
    merge_enabled: bool = True
    push_enabled: bool = False
    push_branches: list[str] = field(default_factory=list)
    fail_on_severity: str = "HIGH"
    block_merge: bool = True
    ignores: list[IgnoreRule] = field(default_factory=list)
    paths: list[str] = field(default_factory=lambda: ["."])
    exclude_paths: list[str] = field(default_factory=list)
    config_file: str | None = None

    def scan_enabled_for(self, mode: str, branch: str = "") -> bool:
        if mode == "pr":
            return self.pr_enabled
        if mode == "merge":
            return self.merge_enabled
        if mode == "push":
            if not self.push_enabled:
                return False
            if not self.push_branches:
                return True
            return branch in self.push_branches
        return False

    def threshold_rank(self) -> int:
        if self.fail_on_severity == "NONE":
            return 99
        return SEVERITY_RANK.get(self.fail_on_severity, SEVERITY_RANK["HIGH"])

    def is_ignored(self, ids: set[str] | frozenset[str], today: date | None = None) -> bool:
        return any(rule.id in ids and rule.is_active(today) for rule in self.ignores)

    def is_blocking(self, finding: Any) -> bool:
        """Unknown severity is treated as blocking so nothing quietly slips through."""
        if self.fail_on_severity == "NONE":
            return False
        if getattr(finding, "severity", "UNKNOWN") == "UNKNOWN":
            return True
        return int(getattr(finding, "rank", 0)) >= self.threshold_rank()


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _parse_date(value: Any, context: str) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ConfigError(f"{context}: expected YYYY-MM-DD, got {value!r}") from exc
    raise ConfigError(f"{context}: expected a date, got {value!r}")


def _as_bool(value: Any, context: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ConfigError(f"{context}: expected true or false, got {value!r}")


def _as_string_list(value: Any, context: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ConfigError(f"{context}: expected a list of strings, got {value!r}")


def parse_config(data: dict[str, Any] | None, config_file: str | None = None) -> Config:
    """Validate a parsed config mapping and merge it with the defaults."""
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError("the config file must contain a YAML mapping")

    # PyYAML follows YAML 1.1, where the bare word `on` becomes the boolean True.
    if True in data:
        data = {**data, "on": data[True]}
        del data[True]

    merged = _deep_merge(DEFAULT_CONFIG, data)

    if merged.get("version") != 1:
        raise ConfigError(f"version must be 1, got {merged.get('version')!r}")

    on = merged["on"]
    policy = merged["policy"]
    scan = merged["scan"]

    severity = str(policy.get("fail_on_severity", "HIGH")).upper()
    if severity not in SEVERITY_LEVELS:
        raise ConfigError(
            f"policy.fail_on_severity must be one of {', '.join(SEVERITY_LEVELS)}"
        )

    raw_ignores = policy.get("ignore_cves") or []
    if not isinstance(raw_ignores, list):
        raise ConfigError("policy.ignore_cves: expected a list")

    ignores: list[IgnoreRule] = []
    for index, item in enumerate(raw_ignores):
        # A plain string is accepted as a shortcut for `- id: ...`.
        if isinstance(item, str):
            ignores.append(IgnoreRule(id=item.strip()))
            continue
        if not isinstance(item, dict):
            raise ConfigError(f"policy.ignore_cves[{index}]: expected a string or a mapping")
        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ConfigError(f"policy.ignore_cves[{index}]: 'id' is required")
        ignores.append(
            IgnoreRule(
                id=rule_id.strip(),
                reason=str(item.get("reason", "")),
                expires=_parse_date(item.get("expires"), f"policy.ignore_cves[{index}].expires"),
            )
        )

    paths = _as_string_list(scan.get("paths"), "scan.paths") or ["."]
    excludes = _as_string_list(scan.get("exclude_paths"), "scan.exclude_paths")

    return Config(
        pr_enabled=_as_bool(on["pull_request"]["enabled"], "on.pull_request.enabled"),
        pr_diff_only=_as_bool(on["pull_request"]["diff_only"], "on.pull_request.diff_only"),
        pr_comment_enabled=_as_bool(
            on["pull_request"].get("comment", True), "on.pull_request.comment"
        ),
        merge_enabled=_as_bool(on["merge"]["enabled"], "on.merge.enabled"),
        push_enabled=_as_bool(on["push"]["enabled"], "on.push.enabled"),
        push_branches=_as_string_list(on["push"].get("branches"), "on.push.branches"),
        fail_on_severity=severity,
        block_merge=_as_bool(policy.get("block_merge", True), "policy.block_merge"),
        ignores=ignores,
        paths=paths,
        exclude_paths=excludes,
        config_file=config_file,
    )


def load_config(root: Path) -> Config:
    """Load .osv-pulse.yml from a checkout. Missing file means use all defaults."""
    for filename in CONFIG_FILENAMES:
        path = root / filename
        if path.is_file():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise ConfigError(f"could not parse {filename}: {exc}") from exc
            return parse_config(data, config_file=filename)
    return parse_config(None)

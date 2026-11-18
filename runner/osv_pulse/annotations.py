"""Turn osv-scanner's SARIF output into GitHub check annotations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

MAX_ANNOTATIONS = 50
MAX_MESSAGE_LENGTH = 65000


def _file_path(uri: str, root: Path) -> str:
    if not uri:
        return ""
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        candidate = Path(unquote(url2pathname(parsed.path)))
    elif parsed.scheme:
        return ""
    else:
        candidate = Path(unquote(uri))
    try:
        return candidate.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return ""


def _result_ids(result: dict[str, Any], rule: dict[str, Any]) -> set[str]:
    ids = {str(result.get("ruleId", ""))}
    ids.update(str(item) for item in (rule.get("deprecatedIds") or []))
    ids.add(str(rule.get("id", "")))
    return {item for item in ids if item}


def build_annotations(
    sarif_path: Path,
    root: Path,
    allowed_ids: Iterable[str],
    blocking_ids: Iterable[str],
    limit: int = MAX_ANNOTATIONS,
) -> tuple[list[dict[str, Any]], bool]:
    """Return (annotations, was_truncated). Missing or invalid SARIF is not fatal."""
    if not sarif_path.is_file():
        return [], False
    try:
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return [], False

    allowed = set(allowed_ids)
    blocking = set(blocking_ids)
    annotations: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()

    for run in sarif.get("runs") or []:
        rules = (((run.get("tool") or {}).get("driver") or {}).get("rules")) or []
        for result in run.get("results") or []:
            rule_index = result.get("ruleIndex")
            rule = (
                rules[rule_index]
                if isinstance(rule_index, int) and 0 <= rule_index < len(rules)
                else {}
            )
            matched = _result_ids(result, rule) & allowed
            if not matched:
                continue

            location = (result.get("locations") or [{}])[0]
            physical = location.get("physicalLocation") or {}
            path = _file_path((physical.get("artifactLocation") or {}).get("uri", ""), root)
            if not path:
                continue

            region = physical.get("region") or {}
            try:
                start = max(1, int(region.get("startLine", 1)))
                end = max(start, int(region.get("endLine", start)))
            except (TypeError, ValueError):
                start = end = 1

            rule_id = str(result.get("ruleId", "vulnerability"))
            identity = (path, start, rule_id)
            if identity in seen:
                continue
            seen.add(identity)

            message = str((result.get("message") or {}).get("text", rule_id))
            annotations.append(
                {
                    "path": path,
                    "start_line": start,
                    "end_line": end,
                    "annotation_level": "failure" if matched & blocking else "warning",
                    "title": rule_id[:200],
                    "message": message[:MAX_MESSAGE_LENGTH],
                }
            )
            if len(annotations) >= limit:
                return annotations, True

    return annotations, False

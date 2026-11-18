"""Convert osv-scanner JSON output into a small, stable finding format."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# CVSS v3.1 base score weights (https://www.first.org/cvss/v3.1/specification-document).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


def cvss31_base_score(vector: str) -> float | None:
    """Compute a CVSS v3.1 base score from a vector string. Returns None if unparseable."""
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
        if not metrics.get("CVSS", "").startswith("3."):
            return None
        scope_changed = metrics["S"] == "C"
        iss = 1 - (
            (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        )
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[metrics["PR"]]
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
        if impact <= 0:
            return 0.0
        raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
        # Round up to one decimal, the way CVSS specifies.
        return float(Decimal(str(min(raw, 10))).quantize(Decimal("0.1"), rounding=ROUND_CEILING))
    except (KeyError, ValueError, AttributeError):
        return None


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def severity_from_vuln(vuln: dict[str, Any]) -> tuple[str, float | None]:
    """Prefer the ecosystem's own severity label, otherwise use a CVSS v3 vector."""
    specific = vuln.get("database_specific") or {}
    label = str(specific.get("severity", "")).upper().replace("MODERATE", "MEDIUM")
    if label in SEVERITY_RANK and label != "UNKNOWN":
        return label, None

    best_score: float | None = None
    for entry in vuln.get("severity") or []:
        vector = entry.get("score", "")
        if not isinstance(vector, str):
            continue
        # CVSS v4 uses a different formula; leave it UNKNOWN unless the
        # advisory also provides an ecosystem severity label (handled above).
        if "CVSS:3" in vector:
            score = cvss31_base_score(vector)
            if score is not None and (best_score is None or score > best_score):
                best_score = score
    return severity_from_score(best_score), best_score


def _fixed_version(vuln: dict[str, Any]) -> str | None:
    specific = vuln.get("database_specific") or {}
    if specific.get("fixed_version"):
        return str(specific["fixed_version"])
    for affected in vuln.get("affected") or []:
        for item_range in affected.get("ranges") or []:
            for event in item_range.get("events") or []:
                if event.get("fixed"):
                    return str(event["fixed"])
    return None


def _relative_path(raw: str, root: Path) -> str:
    if not raw:
        return ""
    path = Path(raw)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return raw.replace("\\", "/")
    cleaned = raw.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


@dataclass(frozen=True)
class Finding:
    path: str
    package: str
    version: str
    ecosystem: str
    vuln_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    severity: str
    cvss: float | None
    summary: str
    fixed_version: str | None
    source_type: str

    @property
    def canonical(self) -> str:
        ids = set(self.vuln_ids) | set(self.aliases)
        preferred = sorted(i for i in ids if i.startswith(("CVE-", "GHSA-")))
        return preferred[0] if preferred else (sorted(ids)[0] if ids else "UNKNOWN")

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Identity used for before/after comparison."""
        return (self.path, self.package, self.version, self.canonical)

    @property
    def all_ids(self) -> frozenset[str]:
        return frozenset(set(self.vuln_ids) | set(self.aliases))

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)


def parse_findings(data: dict[str, Any] | None, root: Path) -> list[Finding]:
    """Parse osv-scanner's --format json output."""
    if not data:
        return []
    findings: dict[tuple[str, str, str, str], Finding] = {}

    for result in data.get("results") or []:
        source = result.get("source") or {}
        path = _relative_path(str(source.get("path", "")), root)
        source_type = str(source.get("type", "unknown"))

        for package_result in result.get("packages") or []:
            package = package_result.get("package") or {}
            name = str(package.get("name", ""))
            version = str(package.get("version", ""))
            ecosystem = str(package.get("ecosystem", ""))
            vulnerabilities = [
                vuln for vuln in (package_result.get("vulnerabilities") or []) if isinstance(vuln, dict)
            ]
            if not vulnerabilities:
                continue

            groups = package_result.get("groups") or [
                {"ids": [vuln.get("id") for vuln in vulnerabilities]}
            ]
            for group in groups:
                group_ids = set(group.get("ids") or [])
                chosen = [v for v in vulnerabilities if v.get("id") in group_ids] or vulnerabilities
                aliases: set[str] = set()
                vuln_ids: set[str] = set()
                best: tuple[int, str, float | None, dict[str, Any]] | None = None
                fixed: str | None = None
                for vuln in chosen:
                    vuln_ids.add(str(vuln.get("id", "")))
                    aliases.update(str(item) for item in (vuln.get("aliases") or []))
                    severity, score = severity_from_vuln(vuln)
                    if best is None or SEVERITY_RANK[severity] > best[0]:
                        best = (SEVERITY_RANK[severity], severity, score, vuln)
                    fixed = fixed or _fixed_version(vuln)

                if best is None:
                    continue
                _, severity, score, advisory = best
                details = str(advisory.get("details") or "").splitlines()
                summary = str(advisory.get("summary") or (details[0] if details else "")).strip()

                finding = Finding(
                    path=path,
                    package=name,
                    version=version,
                    ecosystem=ecosystem,
                    vuln_ids=tuple(sorted(v for v in vuln_ids if v)),
                    aliases=tuple(sorted(aliases)),
                    severity=severity,
                    cvss=score,
                    summary=summary[:500],
                    fixed_version=fixed,
                    source_type=source_type,
                )
                findings.setdefault(finding.key, finding)

    return sorted(findings.values(), key=lambda item: (-item.rank, item.path, item.package, item.canonical))

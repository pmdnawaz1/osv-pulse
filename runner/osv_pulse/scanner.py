"""Run the osv-scanner command line tool and read its results."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .models import Finding, parse_findings


@dataclass
class ScanResult:
    findings: list[Finding]
    raw: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    exit_code: int = 0


class Scanner:
    def __init__(self, binary: str, config: Config, timeout: int = 900):
        self.binary = binary
        self.config = config
        self.timeout = timeout

    def build_command(self, target: Path, output: Path, fmt: str = "json") -> list[str]:
        command = [
            self.binary,
            "scan",
            "source",
            "--format",
            fmt,
            "--output-file",
            str(output),
        ]

        for raw_path in self.config.paths:
            path = Path(raw_path)
            if not path.is_absolute():
                path = target / path
            if path.is_dir():
                command.append("--recursive")
            command.append(str(path))

        for raw_pattern in self.config.exclude_paths:
            pattern = raw_pattern.strip()
            if pattern.startswith(("g:", "r:", ":")):
                value = pattern
            elif pattern.endswith("/**"):
                value = f"g:**/{pattern}"
            else:
                value = f"g:{pattern}"
            command.append(f"--x-exclude={value}")

        return command

    def run(self, target: Path, output: Path, fmt: str = "json") -> ScanResult:
        command = self.build_command(target, output, fmt)
        completed = subprocess.run(
            command,
            cwd=str(target),
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=False,
        )

        if completed.stderr.strip():
            # osv-scanner writes progress and errors to stderr.
            print(completed.stderr.strip()[-4000:], flush=True)

        warnings: list[str] = []
        if completed.returncode == 128:
            warnings.append("No dependency files were found in the scanned paths.")
        elif completed.returncode > 1:
            warnings.append(f"osv-scanner exited with code {completed.returncode}.")

        raw: dict[str, Any] = {}
        if output.is_file():
            try:
                raw = json.loads(output.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                warnings.append(f"Could not read scan output: {exc}")
        elif completed.returncode not in (128,):
            warnings.append("osv-scanner did not write a result file.")

        return ScanResult(
            findings=parse_findings(raw, target),
            raw=raw,
            warnings=warnings,
            exit_code=completed.returncode,
        )

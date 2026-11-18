import csv
import io
import tempfile
import unittest
from pathlib import Path

from osv_pulse.report import render_csv
from osv_pulse.models import parse_findings

SAMPLE = {
    "results": [
        {
            "source": {"path": "/repo/package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-aaaa-bbbb-cccc",
                            "aliases": ["CVE-2024-0001"],
                            "summary": "Example issue",
                            "database_specific": {"severity": "HIGH"},
                            "affected": [{"ranges": [{"events": [{"fixed": "1.0.1"}]}]}],
                        }
                    ],
                    "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"]}],
                }
            ],
        }
    ]
}


class CsvTests(unittest.TestCase):
    def test_csv_has_one_row_per_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            findings = parse_findings(SAMPLE, root)

        text = render_csv(findings, {findings[0].canonical}, root, "full")
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["advisory"], "CVE-2024-0001")
        self.assertEqual(row["aliases"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(row["severity"], "HIGH")
        self.assertEqual(row["package"], "left-pad")
        self.assertEqual(row["fixed_version"], "1.0.1")
        self.assertEqual(row["blocking"], "yes")
        self.assertEqual(row["url"], "https://osv.dev/vulnerability/CVE-2024-0001")


if __name__ == "__main__":
    unittest.main()

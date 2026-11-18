import json
import tempfile
import unittest
from pathlib import Path

from osv_pulse.models import cvss31_base_score, parse_findings

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
                            "affected": [
                                {"ranges": [{"events": [{"fixed": "1.0.1"}]}]}
                            ],
                        }
                    ],
                    "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"]}],
                }
            ],
        }
    ]
}


class ModelTests(unittest.TestCase):
    def test_cvss_score(self):
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(cvss31_base_score(vector), 9.8)
        self.assertIsNone(cvss31_base_score("not-a-vector"))

    def test_parse_findings(self):
        findings = parse_findings(SAMPLE, Path("/repo"))
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.path, "package-lock.json")
        self.assertEqual(finding.package, "left-pad")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.fixed_version, "1.0.1")
        self.assertIn("CVE-2024-0001", finding.all_ids)
        self.assertEqual(finding.canonical, "CVE-2024-0001")

    def test_key_is_stable_for_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = parse_findings(SAMPLE, root)[0]
            second = parse_findings(json.loads(json.dumps(SAMPLE)), root)[0]
        self.assertEqual(first.key, second.key)

    def test_empty_output_is_safe(self):
        self.assertEqual(parse_findings(None, Path(".")), [])
        self.assertEqual(parse_findings({}, Path(".")), [])


if __name__ == "__main__":
    unittest.main()

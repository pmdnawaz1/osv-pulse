import json
import tempfile
import unittest
from pathlib import Path

from osv_pulse.annotations import build_annotations

SARIF = {
    "runs": [
        {
            "tool": {"driver": {"rules": [{"id": "CVE-2024-0001", "deprecatedIds": ["GHSA-aaaa"]}]}},
            "results": [
                {
                    "ruleId": "CVE-2024-0001",
                    "ruleIndex": 0,
                    "message": {"text": "Example vulnerability"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "file:///repo/package-lock.json"
                                },
                                "region": {"startLine": 12, "endLine": 14},
                            }
                        }
                    ],
                }
            ],
        }
    ]
}


class AnnotationTests(unittest.TestCase):
    def test_builds_an_annotation_with_line_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.sarif"
            path.write_text(json.dumps(SARIF), encoding="utf-8")
            annotations, truncated = build_annotations(
                path, Path("/repo"), {"CVE-2024-0001"}, {"CVE-2024-0001"}
            )
        self.assertFalse(truncated)
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]["path"], "package-lock.json")
        self.assertEqual(annotations[0]["start_line"], 12)
        self.assertEqual(annotations[0]["end_line"], 14)
        self.assertEqual(annotations[0]["annotation_level"], "failure")

    def test_skips_unrelated_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.sarif"
            path.write_text(json.dumps(SARIF), encoding="utf-8")
            annotations, _ = build_annotations(path, Path("/repo"), {"CVE-9999"}, set())
        self.assertEqual(annotations, [])

    def test_missing_file_is_not_fatal(self):
        annotations, truncated = build_annotations(Path("/no/such/file"), Path("/repo"), set(), set())
        self.assertEqual(annotations, [])
        self.assertFalse(truncated)


if __name__ == "__main__":
    unittest.main()

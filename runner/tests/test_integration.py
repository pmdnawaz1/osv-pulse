"""End-to-end test of the runner using a fake osv-scanner binary."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from osv_pulse import main

FAKE_SCANNER = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

args = sys.argv[1:]
fmt = args[args.index("--format") + 1]
out = args[args.index("--output-file") + 1]
root = Path.cwd()
base = root.name == "base"

if fmt == "sarif":
    results = [] if base else [{
        "ruleId": "CVE-2024-0001",
        "ruleIndex": 0,
        "message": {"text": "Example vulnerability in left-pad"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": (root / "go.mod").as_uri()},
                "region": {"startLine": 7},
            }
        }],
    }]
    data = {
        "runs": [{
            "tool": {"driver": {"rules": [{"id": "CVE-2024-0001"}]}},
            "results": results,
        }]
    }
else:
    packages = [] if base else [{
        "package": {"name": "left-pad", "version": "1.0.0", "ecosystem": "Go"},
        "vulnerabilities": [{
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2024-0001"],
            "summary": "Example issue",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"ranges": [{"events": [{"fixed": "1.0.1"}]}]}],
        }],
        "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"]}],
    }]
    data = {"results": [{
        "source": {"path": str(root / "go.mod"), "type": "lockfile"},
        "packages": packages,
    }] if not base else []}

Path(out).write_text(json.dumps(data), encoding="utf-8")
'''


class FakeGitHubClient:
    bodies: list[dict] = []
    comments: list[dict] = []
    comment_calls: list[str] = []

    def __init__(self, token, **kwargs):
        pass

    def create_check_run(self, owner, repo, body):
        self.bodies.append(body)
        return 201, {}

    def list_issue_comments(self, owner, repo, number):
        return list(self.comments)

    def create_issue_comment(self, owner, repo, number, body):
        self.comments.append({"id": 1, "body": body})
        self.comment_calls.append("create")
        return 201, {}

    def update_issue_comment(self, owner, repo, comment_id, body):
        self.comments[0] = {"id": comment_id, "body": body}
        self.comment_calls.append("update")
        return 200, {}


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        FakeGitHubClient.bodies = []
        FakeGitHubClient.comments = []
        FakeGitHubClient.comment_calls = []
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.target = self.root / "target"
        self.base = self.root / "base"
        self.work = self.root / "work"
        for path in (self.target, self.base, self.work):
            path.mkdir()
        (self.target / "go.mod").write_text("module example.com/a\n", encoding="utf-8")
        (self.base / "go.mod").write_text("module example.com/a\n", encoding="utf-8")

        scanner = self.root / "fake-scanner"
        scanner.write_text(FAKE_SCANNER, encoding="utf-8")
        scanner.chmod(0o755)
        self.scanner = scanner

        self.payload = {
            "source": "osv-pulse",
            "mode": "pr",
            "event": "pull_request",
            "repository": {"owner": "acme", "name": "shop", "fullName": "acme/shop"},
            "headSha": "a" * 40,
            "baseSha": "b" * 40,
            "pr": {"number": 42},
        }

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, config_text=""):
        if config_text:
            (self.target / ".osv-pulse.yml").write_text(config_text, encoding="utf-8")
        env = {
            "OSV_PULSE_PAYLOAD": json.dumps(self.payload),
            "OSV_PULSE_TARGET_DIR": str(self.target),
            "OSV_PULSE_BASE_DIR": str(self.base),
            "OSV_PULSE_WORKDIR": str(self.work),
            "OSV_PULSE_TOKEN": "test-token",
            "OSV_SCANNER_BIN": str(self.scanner),
            "GITHUB_REPOSITORY": "acme/osv-pulse-runner",
            "GITHUB_RUN_ID": "123456",
        }
        with patch.dict(os.environ, env), patch.object(main, "GitHubClient", FakeGitHubClient):
            return main.main()

    def test_new_finding_fails_the_check_and_adds_annotations(self):
        code = self.run_main()
        self.assertEqual(code, 0)
        body = FakeGitHubClient.bodies[0]
        self.assertEqual(body["conclusion"], "failure")
        self.assertIn("CVE-2024-0001", body["output"]["summary"])
        self.assertEqual(len(body["output"]["annotations"]), 1)
        self.assertEqual(body["output"]["annotations"][0]["path"], "go.mod")
        self.assertEqual(body["output"]["annotations"][0]["start_line"], 7)

    def test_pre_existing_findings_are_not_counted(self):
        # Make the base scan report the same package by changing the fake script.
        self.scanner.write_text(FAKE_SCANNER.replace('root.name == "base"', 'False'), encoding="utf-8")
        code = self.run_main()
        body = FakeGitHubClient.bodies[0]
        self.assertEqual(body["conclusion"], "success")
        self.assertIn("0 new vulnerabilities", body["output"]["summary"])
        self.assertEqual(code, 0)

    def test_warn_only_publishes_neutral_check(self):
        code = self.run_main(
            "version: 1\npolicy:\n  block_merge: false\n"
        )
        body = FakeGitHubClient.bodies[0]
        self.assertEqual(body["conclusion"], "neutral")
        self.assertEqual(code, 0)

    def test_disabled_trigger_skips_the_scan(self):
        code = self.run_main(
            "version: 1\non:\n  pull_request:\n    enabled: false\n"
        )
        body = FakeGitHubClient.bodies[0]
        self.assertEqual(body["conclusion"], "neutral")
        self.assertIn("skipped", body["output"]["title"])
        self.assertEqual(code, 0)
    def test_pr_comment_is_created_with_findings(self):
        self.run_main()
        self.assertEqual(FakeGitHubClient.comment_calls, ["create"])
        body = FakeGitHubClient.comments[0]["body"]
        self.assertIn("osv-pulse:managed-comment", body)
        self.assertIn("CVE-2024-0001", body)
        self.assertIn("acme/osv-pulse-runner/actions/runs/123456", body)
        csv_text = (self.work / "findings.csv").read_text(encoding="utf-8")
        self.assertIn("CVE-2024-0001", csv_text)
        self.assertIn("acme/shop", csv_text)

    def test_pr_comment_is_updated_not_duplicated(self):
        self.run_main()
        self.run_main()
        self.assertEqual(FakeGitHubClient.comment_calls, ["create", "update"])
        self.assertEqual(len(FakeGitHubClient.comments), 1)

    def test_pr_comment_can_be_disabled(self):
        self.run_main("version: 1\non:\n  pull_request:\n    comment: false\n")
        self.assertEqual(FakeGitHubClient.comment_calls, [])


if __name__ == "__main__":
    unittest.main()

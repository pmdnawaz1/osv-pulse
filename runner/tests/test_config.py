import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from osv_pulse.config import ConfigError, load_config, parse_config


class ConfigTests(unittest.TestCase):
    def test_defaults_without_a_config_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(Path(tmp))
        self.assertTrue(config.pr_enabled)
        self.assertTrue(config.pr_diff_only)
        self.assertTrue(config.merge_enabled)
        self.assertFalse(config.push_enabled)
        self.assertEqual(config.fail_on_severity, "HIGH")
        self.assertTrue(config.block_merge)
        self.assertEqual(config.paths, ["."])

    def test_file_values_override_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".osv-pulse.yml").write_text(
                """
version: 1
on:
  pull_request:
    diff_only: false
  push:
    enabled: true
    branches: [main]
policy:
  fail_on_severity: CRITICAL
  block_merge: false
  ignore_cves:
    - id: GHSA-test
      reason: reviewed
      expires: "2030-01-01"
scan:
  exclude_paths: [test/**]
""",
                encoding="utf-8",
            )
            config = load_config(root)

        self.assertFalse(config.pr_diff_only)
        self.assertTrue(config.pr_enabled)
        self.assertTrue(config.push_enabled)
        self.assertTrue(config.scan_enabled_for("push", "main"))
        self.assertFalse(config.scan_enabled_for("push", "dev"))
        self.assertEqual(config.fail_on_severity, "CRITICAL")
        self.assertFalse(config.block_merge)
        self.assertEqual(config.exclude_paths, ["test/**"])
        self.assertEqual(config.ignores[0].id, "GHSA-test")
        self.assertEqual(config.config_file, ".osv-pulse.yml")

    def test_ignore_rules_expire(self):
        today = date.today()
        active = parse_config(
            {"policy": {"ignore_cves": [{"id": "CVE-1", "expires": today.isoformat()}]}}
        )
        expired = parse_config(
            {
                "policy": {
                    "ignore_cves": [
                        {"id": "CVE-1", "expires": (today - timedelta(days=1)).isoformat()}
                    ]
                }
            }
        )
        self.assertTrue(active.is_ignored({"CVE-1"}))
        self.assertFalse(expired.is_ignored({"CVE-1"}))

    def test_string_ignore_shortcut(self):
        config = parse_config({"policy": {"ignore_cves": ["CVE-2024-1234"]}})
        self.assertTrue(config.is_ignored({"CVE-2024-1234"}))

    def test_invalid_values_are_rejected(self):
        with self.assertRaises(ConfigError):
            parse_config({"version": 2})
        with self.assertRaises(ConfigError):
            parse_config({"policy": {"fail_on_severity": "VERY_HIGH"}})
        with self.assertRaises(ConfigError):
            parse_config({"policy": {"ignore_cves": [{"reason": "no id"}]}})
        with self.assertRaises(ConfigError):
            parse_config({"policy": {"ignore_cves": [{"id": "x", "expires": "next week"}]}})

    def test_high_threshold_only_blocks_high_and_above(self):
        from types import SimpleNamespace

        config = parse_config({})
        medium = SimpleNamespace(severity="MEDIUM", rank=2)
        high = SimpleNamespace(severity="HIGH", rank=3)
        unknown = SimpleNamespace(severity="UNKNOWN", rank=0)
        self.assertFalse(config.is_blocking(medium))
        self.assertTrue(config.is_blocking(high))
        self.assertTrue(config.is_blocking(unknown))

    def test_none_threshold_never_blocks(self):
        config = parse_config({"policy": {"fail_on_severity": "NONE"}})

        class FakeFinding:
            severity = "CRITICAL"
            rank = 4

        self.assertFalse(config.is_blocking(FakeFinding()))


if __name__ == "__main__":
    unittest.main()

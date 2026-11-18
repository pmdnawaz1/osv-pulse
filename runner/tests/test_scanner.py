import tempfile
import unittest
from pathlib import Path

from osv_pulse.config import parse_config
from osv_pulse.scanner import Scanner


class ScannerTests(unittest.TestCase):
    def test_command_contains_recursive_and_excludes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "go.mod").write_text("module example.com/a\n", encoding="utf-8")
            config = parse_config(
                {
                    "scan": {
                        "paths": [".", "go.mod"],
                        "exclude_paths": ["test/**", "docs", "g:**/samples/**"],
                    }
                }
            )
            command = Scanner("osv-scanner", config).build_command(
                target, target / "out.json"
            )

        self.assertEqual(command[0], "osv-scanner")
        self.assertIn("scan", command)
        self.assertIn("--format", command)
        self.assertIn("--recursive", command)
        self.assertIn("--x-exclude=g:**/test/**", command)
        self.assertIn("--x-exclude=g:docs", command)
        self.assertIn("--x-exclude=g:**/samples/**", command)
        self.assertIn(str(target / "go.mod"), command)


if __name__ == "__main__":
    unittest.main()

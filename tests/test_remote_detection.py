import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solver"))
sys.path.insert(0, str(ROOT / "research"))

import solve_remote


class HeaderDetectionTests(unittest.TestCase):
    def test_extracts_exact_php_version(self) -> None:
        self.assertEqual(
            solve_remote.php_version_from_headers({"x-powered-by": "PHP/8.4.26"}),
            "8.4.26",
        )

    def test_rejects_missing_or_malformed_banner(self) -> None:
        self.assertIsNone(solve_remote.php_version_from_headers({}))
        self.assertIsNone(
            solve_remote.php_version_from_headers({"x-powered-by": "PHP/8.4"})
        )


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solver"))
sys.path.insert(0, str(ROOT / "research"))

from profile_inventory import load_profiles, validate


class ProfileInventoryTests(unittest.TestCase):
    def test_profiles_are_valid_and_unique(self) -> None:
        records = load_profiles()
        self.assertGreaterEqual(len(records), 11)
        errors = validate(records)
        self.assertEqual(errors, [])

    def test_verified_profiles_have_complete_chain(self) -> None:
        records = load_profiles()
        enabled = [row for row in records if row["rce"]]
        self.assertGreaterEqual(len(enabled), 5)
        for row in enabled:
            self.assertTrue(row["heap_leak"])
            self.assertTrue(row["libphp_leak"])
            self.assertNotEqual(row["stage1"], "-")
            self.assertNotEqual(row["stage2"], "-")
            self.assertNotEqual(row["htdata"], "-")


if __name__ == "__main__":
    unittest.main()

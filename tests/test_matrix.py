import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solver"))
sys.path.insert(0, str(ROOT / "research"))

from calibrate_image import BRANCH_MATRIX, HISTORICAL_MATRIX, VERIFIED_MATRIX
from matrix_runner import MATRIXES, deduplicate


class MatrixTests(unittest.TestCase):
    def test_full_matrix_has_no_duplicate_image_platform(self) -> None:
        entries = deduplicate(MATRIXES["full"])
        identities = [(row["image"], row["platform"]) for row in entries]
        self.assertEqual(len(identities), len(set(identities)))

    def test_runner_and_calibrator_matrices_agree(self) -> None:
        runner_verified = {(row["image"], row["platform"]) for row in MATRIXES["verified"]}
        calibrator_verified = set(VERIFIED_MATRIX)
        self.assertEqual(runner_verified, calibrator_verified)

        runner_branches = {(row["image"], row["platform"]) for row in MATRIXES["branches"]}
        calibrator_branches = {row for row in BRANCH_MATRIX}
        self.assertEqual(runner_branches, calibrator_branches)

        runner_historical = {(row["image"], row["platform"]) for row in MATRIXES["historical"]}
        calibrator_historical = set(HISTORICAL_MATRIX)
        self.assertEqual(runner_historical, calibrator_historical)

    def test_verified_matrix_contains_all_remote_builds(self) -> None:
        identities = {(row["version"], row["arch"]) for row in MATRIXES["verified"]}
        expected = {
            ("8.4.25", "aarch64"),
            ("8.4.26", "amd64"),
            ("8.5.10", "aarch64"),
            ("8.5.11", "aarch64"),
            ("8.5.11", "amd64"),
        }
        self.assertTrue(expected.issubset(identities))


if __name__ == "__main__":
    unittest.main()

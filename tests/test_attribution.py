import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class AttributionTests(unittest.TestCase):
    def test_upstream_exploit_authorship_is_explicit(self) -> None:
        text = (ROOT / "ACKNOWLEDGEMENTS.md").read_text(encoding="utf-8")
        self.assertIn("9bie and contributors", text)
        self.assertIn("https://github.com/9bie/php2shell-bypass-aslr-exp", text)
        self.assertIn("4586f5cc120c82fd468b17469202bac629810ad9", text)
        self.assertIn("does **not** redistribute", text)

        metadata = json.loads((ROOT / "solver/upstream.json").read_text())
        self.assertEqual(metadata["attribution"]["authors"], ["9bie and contributors"])
        self.assertFalse(metadata["attribution"]["redistributed"])

    def test_official_advisory_credits_are_preserved(self) -> None:
        text = (ROOT / "ACKNOWLEDGEMENTS.md").read_text(encoding="utf-8")
        for handle in ("lcfr-hax", "sagitzadik-wiz", "tomash-areion", "amyb-oai"):
            self.assertIn(handle, text)
        for handle in ("arnaud-lb", "iluuu1994", "bukka", "ndossche"):
            self.assertIn(handle, text)


if __name__ == "__main__":
    unittest.main()

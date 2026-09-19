#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Tests for the corpus itself.

The corpus is the specification's enforcement mechanism, so a malformed corpus
silently weakens every implementation that replays it. validate-corpus.py is
the gate; these are the cases that gate must keep catching.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class CorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = json.loads((ROOT / "corpus/digest/cases.json").read_text(encoding="utf-8"))
        self.security = json.loads((ROOT / "corpus/security/corpus.json").read_text(encoding="utf-8"))

    def test_validator_passes_on_the_committed_corpus(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "conformance/validate-corpus.py")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_no_case_collides_under_case_folding(self) -> None:
        # A vector generated on a case-insensitive filesystem describes fewer
        # files than the same case produces on Linux, and fails there as an
        # inexplicable digest mismatch. This shipped once.
        for case in self.digest["cases"]:
            files = case.get("files", {})
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    len({name.lower() for name in files}), len(files),
                    "names differing only by case are one file on macOS",
                )

    def test_every_digest_vector_explains_itself(self) -> None:
        # A vector that fails without saying which rule it isolates leaves the
        # next person diffing two hashes.
        for case in self.digest["cases"]:
            with self.subTest(case=case["name"]):
                self.assertTrue(case.get("why"), "no 'why'")
                self.assertRegex(case["expected_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_cases_that_must_differ_do(self) -> None:
        distinct = {
            c["name"]: c["expected_digest"]
            for c in self.digest["cases"] if "same_digest_as" not in c
        }
        self.assertEqual(
            len(set(distinct.values())), len(distinct),
            "two cases that must produce different digests collide",
        )

    def test_every_pattern_rule_carries_an_inline_case_flag(self) -> None:
        # Case-insensitivity as a host compile flag does not survive export,
        # and the two implementations then disagree on case. This shipped once.
        for path in sorted((ROOT / "rules").glob("*.toml")):
            text = path.read_text(encoding="utf-8")
            match = re.search(r"^pattern = '''(.*?)'''", text, re.MULTILINE | re.DOTALL)
            if match:
                with self.subTest(rule=path.stem):
                    self.assertTrue(match.group(1).startswith("(?i)"), "no inline (?i)")
                    self.assertNotIn("\\\\", match.group(1), "doubled backslash")

    def test_security_corpus_covers_every_rule_category(self) -> None:
        categories = {
            re.search(r'^category = "(.*?)"', p.read_text(encoding="utf-8"), re.MULTILINE).group(1)
            for p in (ROOT / "rules").glob("*.toml")
        }
        covered = {
            want["category"]
            for case in self.security["cases"]
            for want in case.get("must_detect", [])
        }
        self.assertEqual(categories - covered - {"scan_limit"}, set(), "uncovered categories")

    def test_a_benign_case_exists(self) -> None:
        # Without one, a rule set that flags everything scores perfectly.
        self.assertTrue(
            any(c.get("must_not_detect") for c in self.security["cases"]),
            "no benign case: false positives would go unmeasured",
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)

# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""validate-advisories.py must be able to fail."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("validate_advisories", ROOT / "conformance" / "validate-advisories.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AdvisoryVectorTests(unittest.TestCase):
    def copy(self) -> Path:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        shutil.copytree(module.VECTORS, tmp / "v")
        return tmp / "v"

    def test_the_vectors_hold(self) -> None:
        self.assertEqual(module.main(), 0)

    def test_a_wrong_expectation_fails(self) -> None:
        vectors = self.copy()
        cases = json.loads((vectors / "cases.json").read_text(encoding="utf-8"))
        cases["cases"][0]["expected"] = "clean"
        (vectors / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
        self.assertEqual(module.main(vectors), 1)

    def test_an_edited_feed_no_longer_verifies(self) -> None:
        vectors = self.copy()
        (vectors / "feed.json").write_text((vectors / "feed.json").read_text(encoding="utf-8").replace("001", "009"), encoding="utf-8")
        self.assertEqual(module.main(vectors), 1)

    def test_malformed_advisories_are_named(self) -> None:
        bad = {"advisories": [
            {"id": "CVE-1", "published": "yesterday", "affected": []},
            {"id": "AGT-ADV-2026-001", "modified": "2026-09-24T00:00:00Z", "affected": [{"package": {"ecosystem": "PyPI"}, "ecosystem_specific": {"digests": ["md5:x"]}}]},
            {"id": "AGT-ADV-2026-001", "modified": "2026-09-24T00:00:00Z", "affected": [{"package": {"ecosystem": "AgtMLS"}, "ecosystem_specific": {"digests": ["sha256:" + "0" * 64]}}]},
        ]}
        problems = " | ".join(module.feed_problems(bad))
        for text in ("not AGT-ADV-YYYY-NNN", "published is not", "OSV requires modified", "no affected", "ecosystem is not AgtMLS", "sha256: digests", "not unique"):
            self.assertIn(text, problems)

    def test_a_missing_tool_fails_rather_than_skips(self) -> None:
        with mock.patch.object(module.shutil, "which", return_value=None):
            self.assertEqual(module.main(), 1)


if __name__ == "__main__":
    unittest.main()

# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""validate-signatures.py must be able to fail."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("validate_signatures", ROOT / "conformance" / "validate-signatures.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SignatureVectorTests(unittest.TestCase):
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
        cases["cases"][0]["expected"] = "bad_signature"
        (vectors / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
        self.assertEqual(module.main(vectors), 1)

    def test_a_missing_tool_fails_rather_than_skips(self) -> None:
        with mock.patch.object(module.shutil, "which", return_value=None):
            self.assertEqual(module.main(), 1)


if __name__ == "__main__":
    unittest.main()

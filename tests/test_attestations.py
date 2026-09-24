# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""validate-attestations.py must be able to fail."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("validate_attestations", ROOT / "conformance" / "validate-attestations.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class AttestationVectorTests(unittest.TestCase):
    def test_the_vectors_match_their_derivation(self) -> None:
        self.assertEqual(module.main([]), 0)

    def test_a_drifted_vector_fails(self) -> None:
        real = module.derive()
        name = next(iter(real))
        with mock.patch.object(module, "derive", return_value={name: real[name] + " "}):
            self.assertEqual(module.main([]), 1)

    def test_a_scoped_tool_still_escalates_and_network_optional_is_granted(self) -> None:
        table = {"Bash": "executes_commands", "WebFetch": "network_access"}
        md = '---\nname: x\ndescription: Use when x.\nallowed-tools: "Bash(git log:*) WebFetch"\n---\n'
        denied = module.capabilities("x", "sha256:" + "0" * 64, md, {"safety_policy": {}}, table)["predicate"]
        self.assertEqual([e["tool"] for e in denied["escalations"]], ["Bash(git log:*)", "WebFetch"])
        allowed = module.capabilities("x", "sha256:" + "0" * 64, md, {"safety_policy": {"executes_commands": True, "network_access": "optional"}}, table)
        self.assertEqual(allowed["predicate"]["escalations"], [])

    def test_a_missing_capability_table_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            module.tool_capabilities('id = "AGT-CAP-001"\n')


if __name__ == "__main__":
    unittest.main()

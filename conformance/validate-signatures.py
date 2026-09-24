#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Check every signature vector against ssh-keygen -Y verify.

The vectors in corpus/signatures/ describe what a verifier must conclude.
This runs the reference tool on each one and fails if any outcome differs,
so a vector cannot say one thing while the tool does another. It fails,
rather than skipping, when ssh-keygen is absent (spec 7.3).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "corpus" / "signatures"


def outcome(case: dict, spec: dict, directory: Path) -> str:
    if case["signature"] is None:
        return "unsigned"
    with (directory / case["index"]).open("rb") as index:
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(directory / spec["allowed_signers"]),
             "-I", spec["principal"], "-n", spec["namespace"],
             "-s", str(directory / case["signature"]), f"-Overify-time={case['verify_time']}"],
            stdin=index, capture_output=True, text=True, check=False,
        )
    return "verified" if proc.returncode == 0 else "bad_signature"


def main(directory: Path = VECTORS) -> int:
    if shutil.which("ssh-keygen") is None:
        print("FAIL: ssh-keygen is not installed; the signature vectors cannot be checked")
        return 1
    spec = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    errors = []
    for case in spec["cases"]:
        got = outcome(case, spec, directory)
        if got != case["expected"]:
            errors.append(f"{case['name']}: expected {case['expected']}, ssh-keygen says {got}")
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print(f"OK: {len(spec['cases'])} signature vector(s) behave as declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())

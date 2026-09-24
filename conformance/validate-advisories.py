#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Check the advisory feed's shape and every revocation vector.

Each case is evaluated the way chapter 11 says a verifier must: the feed's
signature first (ssh-keygen -Y verify), and only a verified feed is
consulted, matching installed digests against advisories that are not
withdrawn. The outcome and the advisories named must equal the case's.
Fails rather than skips when ssh-keygen is absent (spec 7.3).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "corpus" / "advisories"
ADVISORY_ID = re.compile(r"^AGT-ADV-\d{4}-\d{3,}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def feed_problems(feed: dict) -> list[str]:
    problems = []
    seen = set()
    for advisory in feed.get("advisories", []):
        name = advisory.get("id", "?")
        if not ADVISORY_ID.match(name):
            problems.append(f"{name}: id is not AGT-ADV-YYYY-NNN")
        if name in seen:
            problems.append(f"{name}: id is not unique")
        seen.add(name)
        for field in ("modified", "published", "withdrawn"):
            if field in advisory and not TIMESTAMP.match(advisory[field]):
                problems.append(f"{name}: {field} is not an RFC 3339 UTC timestamp")
        if "modified" not in advisory:
            problems.append(f"{name}: OSV requires modified")
        affected = advisory.get("affected") or []
        if not affected:
            problems.append(f"{name}: no affected entries")
        for entry in affected:
            if entry.get("package", {}).get("ecosystem") != "AgtMLS":
                problems.append(f"{name}: affected ecosystem is not AgtMLS")
            digests = entry.get("ecosystem_specific", {}).get("digests") or []
            if not digests or not all(DIGEST.match(d) for d in digests):
                problems.append(f"{name}: affected needs one or more sha256: digests")
    return problems


def revoked_by(feed: dict, lockfile: dict) -> list[str]:
    """Advisory ids that revoke an installed digest; withdrawn ones do not."""
    installed = {skill["integrity"] for skill in lockfile.get("skills", [])}
    hits = []
    for advisory in feed["advisories"]:
        if "withdrawn" in advisory:
            continue
        digests = {d for entry in advisory["affected"] for d in entry["ecosystem_specific"]["digests"]}
        if digests & installed:
            hits.append(advisory["id"])
    return sorted(hits)


def outcome(case: dict, spec: dict, directory: Path, feed: dict) -> tuple[str, list[str]]:
    if case["signature"] is None:
        return "unsigned", []
    with (directory / spec["feed"]).open("rb") as handle:
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(directory / spec["allowed_signers"]),
             "-I", spec["principal"], "-n", spec["namespace"],
             "-s", str(directory / case["signature"]), f"-Overify-time={spec['verify_time']}"],
            stdin=handle, capture_output=True, text=True, check=False,
        )
    if proc.returncode != 0:
        return "bad_signature", []
    hits = revoked_by(feed, case["lockfile"])
    return ("revoked" if hits else "clean"), hits


def main(directory: Path = VECTORS) -> int:
    if shutil.which("ssh-keygen") is None:
        print("FAIL: ssh-keygen is not installed; the advisory vectors cannot be checked")
        return 1
    spec = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    feed = json.loads((directory / spec["feed"]).read_text(encoding="utf-8"))
    errors = feed_problems(feed)
    for case in spec["cases"]:
        got = outcome(case, spec, directory, feed)
        if got != (case["expected"], case["advisories"]):
            errors.append(f"{case['name']}: expected {case['expected']} {case['advisories']}, got {got[0]} {got[1]}")
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print(f"OK: advisory feed well-formed; {len(spec['cases'])} revocation vector(s) behave as declared")
    return 0


if __name__ == "__main__":
    sys.exit(main())

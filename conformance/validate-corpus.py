#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Check that the corpus and rule data are internally consistent.

The corpus is the specification's enforcement mechanism, so a malformed corpus
silently weakens every implementation that replays it. These checks are cheap
and catch the ways a corpus rots: a rule with no case, a case naming a rule
that does not exist, a digest vector whose declared equality no longer holds.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# --- rules -----------------------------------------------------------

def _pattern_problems(rule_id: str, text: str) -> list[str]:
    """A pattern rule's portability (spec 4.6) and its examples (4.4, 4.5)."""
    errors = []
    pattern = re.search(r"^pattern = '''(.*?)'''", text, re.MULTILINE | re.DOTALL).group(1)
    if not pattern.startswith("(?i)"):
        errors.append(f"{rule_id}: pattern must carry an inline (?i); a host compile flag does not survive export (spec 4.6)")
    if "\\\\" in pattern:
        errors.append(f"{rule_id}: doubled backslash in a TOML literal string (spec 4.6)")
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append(f"{rule_id}: pattern does not compile: {exc}")
    if "[[true_positive]]" not in text:
        errors.append(f"{rule_id}: declares a pattern but no true_positive (spec 4.4)")
    if "[[false_positive]]" not in text and "false_positive_policy" not in text:
        errors.append(
            f"{rule_id}: no false_positive and no false_positive_policy. "
            "A rule with neither has not been tested against reality (spec 4.5)"
        )
    return errors


def rule_problems(path: Path) -> tuple[str | None, list[str]]:
    """(the rule's id, or None when it declares none; its problems)."""
    text = path.read_text(encoding="utf-8")
    match = re.search(r'^id = "(.*?)"', text, re.MULTILINE)
    if not match:
        return None, [f"{path.name}: no id"]
    rule_id = match.group(1)
    errors = []
    if rule_id != path.stem:
        errors.append(f"{path.name}: id {rule_id!r} does not match filename")
    if not re.match(r"^AGT-[A-Z]+-\d{3}$", rule_id):
        errors.append(f"{rule_id}: identifier does not match AGT-<CLASS>-<NNN>")
    selectors = re.search(r"^applies_to = (\[.*\])$", text, re.MULTILINE)
    for selector in json.loads(selectors.group(1)) if selectors else []:
        if not re.fullmatch(r"\*|\*\.[A-Za-z0-9]+|executable", selector):
            errors.append(f"{rule_id}: applies_to selector {selector!r} is not *, *.<ext> or executable (spec 4.11)")
    if "pattern = '''" in text:
        errors += _pattern_problems(rule_id, text)
    return rule_id, errors


# --- digest corpus ---------------------------------------------------

def _digest_case_problems(case: dict, by_name: dict) -> list[str]:
    errors = [f"digest/{case.get('name', '?')}: missing {field}"
              for field in ("name", "why", "expected_digest", "expected_manifest") if field not in case]
    if not str(case.get("expected_digest", "")).startswith("sha256:"):
        errors.append(f"digest/{case['name']}: digest must be sha256:-prefixed (spec 3.10)")
    twin = case.get("same_digest_as")
    if twin and twin not in by_name:
        errors.append(f"digest/{case['name']}: same_digest_as names an unknown case {twin!r}")
    elif twin and case["expected_digest"] != by_name[twin]["expected_digest"]:
        errors.append(f"digest/{case['name']}: declared equal to {twin} but digests differ")
    return errors


def digest_problems(digest: dict) -> list[str]:
    by_name = {c["name"]: c for c in digest["cases"]}
    errors = [e for case in digest["cases"] for e in _digest_case_problems(case, by_name)]
    distinct = {c["name"]: c["expected_digest"] for c in digest["cases"] if "same_digest_as" not in c}
    if len(set(distinct.values())) != len(distinct):
        errors.append("digest: two cases that must differ share a digest")
    return errors


# --- security corpus -------------------------------------------------

def security_problems(security: dict, rule_files: list[Path]) -> list[str]:
    categories = {
        re.search(r'^category = "(.*?)"', p.read_text(encoding="utf-8"), re.MULTILINE).group(1)
        for p in rule_files
    }
    errors = []
    covered: set[str] = set()
    for case in security["cases"]:
        if not case.get("description"):
            errors.append(f"security/{case['name']}: no description, so a failure cannot be explained")
        for want in case.get("must_detect", []):
            covered.add(want["category"])
            if want["category"] not in categories:
                errors.append(f"security/{case['name']}: category {want['category']!r} matches no rule")
    uncovered = categories - covered - {"scan_limit"}
    if uncovered:
        errors.append(f"no security corpus case covers: {', '.join(sorted(uncovered))}")
    return errors


def main() -> int:
    errors: list[str] = []
    rule_files = sorted((ROOT / "rules").glob("*.toml"))
    rule_ids: set[str] = set()
    for path in rule_files:
        rule_id, found = rule_problems(path)
        if rule_id is not None:
            rule_ids.add(rule_id)
        errors += found
    digest = json.loads((ROOT / "corpus/digest/cases.json").read_text(encoding="utf-8"))
    errors += digest_problems(digest)
    security = json.loads((ROOT / "corpus/security/corpus.json").read_text(encoding="utf-8"))
    errors += security_problems(security, rule_files)

    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        print()
        print(f"FAIL: {len(errors)} corpus integrity issue(s)")
        return 1
    print(
        f"OK: corpus well-formed — {len(rule_ids)} rules, "
        f"{len(digest['cases'])} digest vectors, {len(security['cases'])} security cases"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

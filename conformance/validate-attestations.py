#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Derive every attestation vector from its inputs and compare byte for byte.

Chapter 10 says an attestation is a pure function of the skill and the
rule data, rendered canonically. So each vector is rebuilt here from the
inputs it names -- a digest case, a policy fixture -- and must equal the
committed file exactly. A vector that drifts from its derivation, or a
derivation rule that changes without its vectors, fails.

    conformance/validate-attestations.py           # check
    conformance/validate-attestations.py --write   # re-render the vectors
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "corpus" / "attestations"
STATEMENT = "https://in-toto.io/Statement/v1"
MANIFEST = "https://agtmls.dev/manifest/v1"
CAPABILITIES = "https://agtmls.dev/capabilities/v1"


def canonical(value: object) -> str:
    """Spec 10.2: sorted keys, two-space indent, UTF-8 unescaped, one newline."""
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def hexdigest(digest: str) -> str:
    return digest.removeprefix("sha256:")


def manifest(name: str, case: dict) -> dict:
    return {
        "_type": STATEMENT,
        "subject": [{"name": name, "digest": {"sha256": hexdigest(case["expected_digest"])}}],
        "predicateType": MANIFEST,
        "predicate": {
            "digest_algorithm": "agtmls-skill-digest-v1",
            "files": [{"path": e["path"], "digest": {"sha256": e["sha256"]}} for e in case["expected_manifest"]],
        },
    }


def frontmatter_tools(skill_md: str) -> list[str]:
    match = re.match(r"^---[ \t]*\n(.*?)\n---[ \t]*\n", skill_md, re.DOTALL)
    field = re.search(r"^allowed-tools:[ \t]*(.*)$", match.group(1), re.MULTILINE) if match else None
    return re.findall(r"[^\s,()'\"\[\]]+(?:\([^)]*\))?", field.group(1)) if field else []


def capabilities(name: str, digest: str, skill_md: str, metadata: dict, table: dict) -> dict:
    policy = metadata.get("safety_policy", {})
    tools = frontmatter_tools(skill_md)
    escalations = []
    for tool in tools:
        capability = table.get(tool.split("(", 1)[0])
        if capability is None:
            continue
        granted = policy.get(capability) in {"optional", "required"} if capability == "network_access" else bool(policy.get(capability))
        if not granted:
            escalations.append({"tool": tool, "capability": capability})
    return {
        "_type": STATEMENT,
        "subject": [{"name": name, "digest": {"sha256": hexdigest(digest)}}],
        "predicateType": CAPABILITIES,
        "predicate": {"declared_policy": policy, "allowed_tools": tools, "escalations": escalations},
    }


def tool_capabilities(toml: str) -> dict[str, str]:
    """The [tool_capabilities] table, read without tomllib so 3.10 can run
    this, as validate-corpus.py reads rules."""
    section = re.search(r"^\[tool_capabilities\]\n(.*?)(?=^\[|\Z)", toml, re.MULTILINE | re.DOTALL)
    if section is None:
        raise SystemExit("FAIL: AGT-CAP-001 declares no [tool_capabilities] table")
    return dict(re.findall(r'^([A-Za-z][\w]*) = "([a-z_]+)"$', section.group(1), re.MULTILINE))


def derive() -> dict[str, str]:
    digest_cases = {c["name"]: c for c in json.loads((ROOT / "corpus/digest/cases.json").read_text(encoding="utf-8"))["cases"]}
    table = tool_capabilities((ROOT / "rules/AGT-CAP-001.toml").read_text(encoding="utf-8"))
    inputs = json.loads((VECTORS / "inputs.json").read_text(encoding="utf-8"))
    rendered: dict[str, str] = {}
    for item in inputs["manifests"]:
        rendered[item["vector"]] = canonical(manifest(item["skill"], digest_cases[item["digest_case"]]))
    for item in inputs["capabilities"]:
        rendered[item["vector"]] = canonical(capabilities(
            item["skill"], item["digest"], item["files"]["SKILL.md"], json.loads(item["files"]["metadata.json"]), table,
        ))
    return rendered


def main(argv: list[str] | None = None) -> int:
    write = "--write" in (sys.argv[1:] if argv is None else argv)
    errors = []
    for vector, text in derive().items():
        path = VECTORS / vector
        if write:
            path.write_text(text, encoding="utf-8")
        elif not path.exists() or path.read_text(encoding="utf-8") != text:
            errors.append(f"{vector} does not equal its derivation; run --write if the change is intended")
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        return 1
    print(f"OK: attestation vectors {'written' if write else 'match their derivation'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

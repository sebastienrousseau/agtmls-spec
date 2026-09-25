<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 10. Attestations

**Status:** normative, except §10.6, which is reserved until an analyzer
emits it. **Conformance:** L5: both reference implementations reproduce
every vector in [`corpus/attestations/`](../corpus/attestations/) byte for
byte, and `conformance/run.py` compares them with each other.

## 10.1 Purpose

The signed index ([09-signatures.md](09-signatures.md)) says which skills a
release contains. An attestation says something checkable about one skill:
exactly which files it is made of, and which capabilities its frontmatter
grants against the policy it declares. Each is an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
whose subject is the skill, identified by its digest
([03-integrity.md](03-integrity.md)).

## 10.2 Rendering

An attestation is a pure function of the skill and the rule data. It MUST be
rendered canonically: UTF-8, object keys sorted, two-space indentation,
non-ASCII characters unescaped, and a single trailing newline. Two runs over
the same skill MUST produce identical bytes, and the vectors are compared
byte for byte.

An attestation MUST be written outside the skill's directory, at
`attestations/<skill>/<kind>.intoto.json`. Inside it, it would change the
digest it attests.

## 10.3 Subject

```json
"subject": [{"name": "<skill name>", "digest": {"sha256": "<hex of the skill digest>"}}]
```

The digest is the §3.1 skill digest without its `sha256:` prefix, as in-toto
digest sets require.

## 10.4 Manifest — `https://agtmls.dev/manifest/v1`

```json
"predicate": {
  "digest_algorithm": "agtmls-skill-digest-v1",
  "files": [{"path": "SKILL.md", "digest": {"sha256": "<hex>"}}]
}
```

`files` is exactly the §3.1 manifest: every hashed file, in §3.7 order, with
`/` separators. A verifier can therefore recompute the subject digest from
`files` alone, and name the file that differs when it does not match. The
layout follows the in-toto shape used by OpenSSF Model Signing (one subject,
one digest per resource); byte compatibility with a pinned OMS version is not
claimed until it is tested against `model_signing`.

## 10.5 Capabilities — `https://agtmls.dev/capabilities/v1`

```json
"predicate": {
  "declared_policy": {"executes_commands": false, "network_access": "none", "writes_files": false},
  "allowed_tools": ["Read", "Bash(git log:*)"],
  "escalations": [{"tool": "Bash(git log:*)", "capability": "executes_commands"}]
}
```

`declared_policy` is `metadata.json`'s `safety_policy` as written.
`allowed_tools` is the frontmatter field, split on whitespace and commas, a
parenthesised specifier kept with its tool. `escalations` lists, in
`allowed_tools` order, each tool whose capability the policy denies — the
same judgement as `AGT-CAP-001`. Which capability a tool grants is data: the
`[tool_capabilities]` table in [`rules/AGT-CAP-001.toml`](../rules/AGT-CAP-001.toml).
A specifier narrows a tool and still grants its capability. `network_access`
is granted by `optional` or `required`; the others by `true`.

## 10.6 Audit — `https://agtmls.dev/audit/v1`

Reserved for P2.5, defined here so its shape is agreed before it is emitted:

```json
"predicate": {
  "ruleset": {"spec_commit": "<40 hex>", "digest": {"sha256": "<§3.1 digest of rules/>"}},
  "analyzer": {"name": "agtmls", "version": "<version>"},
  "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
  "sarif": {"sha256": "<hex of the SARIF log>"}
}
```

It has no vectors yet: its counts come from running an analyzer, which this
repository does not contain. They arrive with the first implementation.

## 10.7 Signing

An attestation is signed as the index is (§9.2), in a sibling `.sig` file,
under the namespace `agtmls-attestation@v1`, by a key listed in
`allowed_signers` for that namespace. A keyless Sigstore bundle is an optional
second channel (P2.6) and never replaces this one.

## 10.8 Vectors

[`corpus/attestations/inputs.json`](../corpus/attestations/inputs.json) names
the inputs for each vector: a manifest vector names a
[digest case](../corpus/digest/cases.json) and reuses its expected digest and
manifest; a capabilities vector carries its `SKILL.md` and `metadata.json`.
`conformance/validate-attestations.py` rebuilds every vector from its inputs
and fails unless the committed file matches byte for byte.

<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Changelog

This specification versions independently of any implementation, and
deliberately more slowly. Rule identifiers are permanent and are never reused,
including after withdrawal.

## Unreleased

### Changed

- Chapters 9, 10 (except the reserved §10.6) and 11 are normative. Both
  reference implementations reproduce every signature, advisory and
  attestation vector, and `conformance/run.py` compares them with each
  other at the new level **L5 (Trust)**: signature and advisory verdicts
  with their exit codes, and attestations byte for byte.

### Fixed

- The signature, advisory and attestation vectors are checked out as exact
  bytes (`.gitattributes`): Git for Windows rewrote them with CRLF, so
  every signature vector failed there.

### Added

- Three `AGT-CAP-001` corpus cases: `allowed-tools` written
  space-separated, a tool narrowed by a specifier (`Bash(git log:*)`),
  and the same specifier under a policy that admits it. One
  implementation split on commas only and missed the first two while the
  differential stayed green.
- `11-advisories.md` (draft): a signed OSV feed (`AGT-ADV-YYYY-NNN`, digests
  in `ecosystem_specific`, matched on digest never version, `withdrawn`
  honoured) under `agtmls-advisory@v1`, offline by default with an
  opt-in, verify-before-replace `--refresh`. Exit code `6` names the
  advisories, and §11.4 fixes precedence: `5`, then `3`, then `6`, then
  `4`. Six vectors, checked in CI.
- `10-attestations.md` (draft): per-skill in-toto Statements whose subject
  is the skill digest. A manifest predicate (the §3.1 file list, so the
  digest can be recomputed and the differing file named), a capabilities
  predicate (declared policy, granted tools, escalations), and a reserved
  audit predicate. Canonical rendering, written outside the skill,
  signed under `agtmls-attestation@v1`. Four vectors derived from the
  digest corpus and policy fixtures, checked byte for byte in CI.
- `AGT-CAP-001` carries the tool-to-capability table as data
  (`[tool_capabilities]`), which both implementations kept as copies.
- `09-signatures.md` (draft): `index.json` signed with an OpenSSH `SSHSIG`
  under the namespace `agtmls-index@v1`, keys in `allowed_signers` with
  `valid-after`/`valid-before` rotation, and exit codes `4` unsigned, `5`
  bad signature, `6` revoked (reserved). Eight vectors in
  `corpus/signatures/`, checked against `ssh-keygen -Y verify` in CI by
  `validate-signatures.py`; the keys' private halves were discarded.
- §4.11 defines `applies_to`: a pattern rule runs only on files a
  selector matches, and a selector is `*`, `*.<ext>` or `executable` (a file
  beginning with `#!`). `validate-corpus.py` rejects any other form. Four
  corpus cases, one of them a benign file the selectors keep out. An
  implementation must also audit any file beginning with `#!`, so a
  script with no extension and no execute bit is still in scope.
- `AGT-HOOK-003` (MEDIUM): repository hooks run on a lifecycle event
  without a trust gate (`core.hooksPath` into the tree, `.dmux-hooks`,
  `worktree_created`). `AGT-POLICY-006` (HIGH): an unscoped tool family in
  `permissions.allow`. Both are pattern rules, with four corpus cases.
- `AGT-STEG-002` (LOW) and an `emoji_context` table on `AGT-STEG-001`:
  a variation selector directly after an emoji-presentation base, and a
  well-formed subdivision flag, are an emoji as written rather than a
  channel. §4.10 says how an implementation decides from that data.
  The variation selectors supplement (U+E0100 to U+E01EF) joins the
  ranges. Seven corpus cases.
- Eleven rules over the surfaces an agent actually runs: hooks that
  auto-approve or fetch (`AGT-HOOK-001`, `-002`), wildcard tool grants
  (`AGT-CAP-002`), unpinned runners (`AGT-SUPPLY-001`), self-install,
  permission-bypass flags and model output interpolated into a shell
  (`AGT-EXEC-005` to `-007`), command-running MCP tools (`AGT-MCP-001`),
  decode-and-execute payloads (`AGT-PACK-001`), paste-this-command prose
  (`AGT-SOCIAL-001`) and selection gaming (`AGT-SEL-001`). Thirteen corpus
  cases, one with a split-line evasion and one benign pin. Six new classes
  in §4.2.
- Eight specification documents; `00-overview`, `03-integrity`, `04-rules`,
  `06-lockfile` and `07-conformance` are normative.
- Nineteen rules as TOML data, loaded identically by every implementation.
- Forty-four corpus cases across digest, security and rule self-tests.
- A four-level conformance runner that compares implementations to **each
  other**, not only to expected values.

### Fixed

- JSON string escapes hid a phrase from every normalised rule: `Ignore
  previous\n instructions` in a tool description never flattened to
  adjacent words, while the model reads it decoded. §4.3 requires `*.json`
  files be escape-decoded before whitespace is collapsed, with escaped
  whitespace becoming a space so line numbers survive. Two corpus cases.
- The injection rules applied to Markdown, text and executables only, so
  an instruction override inside a JSON MCP tool description was out of
  scope. They apply to every file now, and the execution, payload,
  exfiltration, social and selection rules cover JSON, YAML and TOML,
  where hook and CI commands and tool descriptions live.
- `AGT-EXEC-002` required the `r` flag before the `f`, so `rm -fr /` walked
  past it. Either order matches now, with a true positive and a corpus case.
- `ordering-digits-vs-letters` declared `A.md` and `a.md`, which are the same
  file on a case-insensitive filesystem. The vector recorded a three-file
  manifest and failed on the first Linux run. `validate-corpus.py` now rejects
  any case whose names collide under case folding.

<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Changelog

This specification versions independently of any implementation, and
deliberately more slowly. Rule identifiers are permanent and are never reused,
including after withdrawal.

## Unreleased

### Added

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

- `AGT-EXEC-002` required the `r` flag before the `f`, so `rm -fr /` walked
  past it. Either order matches now, with a true positive and a corpus case.
- `ordering-digits-vs-letters` declared `A.md` and `a.md`, which are the same
  file on a case-insensitive filesystem. The vector recorded a three-file
  manifest and failed on the first Linux run. `validate-corpus.py` now rejects
  any case whose names collide under case folding.

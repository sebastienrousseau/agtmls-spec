<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Changelog

This specification versions independently of any implementation, and
deliberately more slowly. Rule identifiers are permanent and are never reused,
including after withdrawal.

## Unreleased

### Added

- Eight specification documents; `00-overview`, `03-integrity`, `04-rules`,
  `06-lockfile` and `07-conformance` are normative.
- Nineteen rules as TOML data, loaded identically by every implementation.
- Forty-four corpus cases across digest, security and rule self-tests.
- A four-level conformance runner that compares implementations to **each
  other**, not only to expected values.

### Fixed

- `AGT-CAP-001` did not say how `allowed-tools` is tokenised, and both
  implementations split it on commas only. The Agent Skills form is
  space-separated (`allowed-tools: "Read Glob Bash"`), which that read as one
  tool granting nothing, so the rule could not fire on a real skill. §4.10 now
  makes the tokenisation and the tool-to-capability table normative:
  whitespace and commas separate tools, quotes and `[...]` brackets are
  ignored, and a parenthesised specifier such as `Bash(git log:*)` stays in
  its token and counts as the tool before the `(`. Five security corpus cases
  cover the space-separated, tab-separated, scoped, flow-list and honest-grant
  forms; the first three fail against a comma-only implementation.
- `ordering-digits-vs-letters` declared `A.md` and `a.md`, which are the same
  file on a case-insensitive filesystem. The vector recorded a three-file
  manifest and failed on the first Linux run. `validate-corpus.py` now rejects
  any case whose names collide under case folding.

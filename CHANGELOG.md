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

- `ordering-digits-vs-letters` declared `A.md` and `a.md`, which are the same
  file on a case-insensitive filesystem. The vector recorded a three-file
  manifest and failed on the first Linux run. `validate-corpus.py` now rejects
  any case whose names collide under case folding.

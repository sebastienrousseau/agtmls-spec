<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# ADR 0001 — The corpus is a data manifest, not a directory of fixtures

**Status:** accepted · **Date:** 2026-09-19

## Context

The security corpus needs fixtures that are, by construction, things a
repository's own validators should reject: a malformed `metadata.json`, an
unsigned shell script containing `curl | bash`, a file full of invisible
characters.

Committing those as real files makes them fixtures of the host repository too.
`validate-json-files.py` parses every JSON file and would fail on the malformed
one; `validate-shell-syntax.py` would lint the malicious script; the analyzer
would flag the corpus while scanning the repository that contains it.

## Decision

A corpus case is an entry in a JSON manifest that declares its files as
strings. Runners materialise each case into a temporary directory.

## Consequences

**Good.** The corpus can contain anything, including content no linter would
accept. Invisible characters are written as `\uXXXX` escapes, so they are
visible in review — which matters more here than anywhere else, since the
whole point is content a reviewer cannot see. And a manifest can be replayed
against an implementation that does not exist yet, in a language nobody has
chosen.

**Costly.** A case cannot exercise anything about the filesystem that a
materialiser does not reproduce: file modes, hard links, ordering.

**The trap it did not avoid.** Materialisation happens on whatever filesystem
the runner is on. A vector generated on macOS declared `A.md` and `a.md` —
the same file there, two files on Linux — and shipped a three-file manifest
that failed on the first Linux run. `validate-corpus.py` now rejects any case
whose names collide under case folding, and the runners compare the files they
declared against the files that exist.

## Alternatives rejected

**Fixture directories with an exclusion list in every validator.** Every new
validator would need to know about the exclusion, and the one that forgets
fails confusingly. Correctness by data shape beats correctness by everyone
remembering.

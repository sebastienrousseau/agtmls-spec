<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 0. Overview

**Status:** normative for the documents it lists.

## 0.1 Scope

This specification defines an *agent skill*: a unit of reusable instruction
that a coding agent loads on demand. It covers the on-disk format, the content
address, the registry index, the install lockfile, and the identifiers used by
static analysis.

It does **not** specify how an agent decides to load a skill. Routing is a
model behaviour, not a wire format, and pretending otherwise would freeze a
guess into a standard.

## 0.2 Why a separate specification

The AgtMLS ecosystem has four surfaces — a CLI, a language server, an MCP
server, and a WASM module — and at least two implementation languages. Without
a normative source and a shared corpus, those agree only by coincidence, and
the divergence surfaces as a security hole: a payload one implementation
blocks is one another calls clean.

The corpus in this repository is not documentation of the specification. It
**is** the specification's enforcement mechanism. A rule with no corpus case is
a suggestion.

## 0.3 Document status

| Document | Status |
| :--- | :--- |
| [`01-skill.md`](01-skill.md) | Draft — derived from the reference implementation |
| [`02-metadata.md`](02-metadata.md) | Draft — derived from the reference implementation |
| [`03-integrity.md`](03-integrity.md) | **Normative**, with test vectors |
| [`04-rules.md`](04-rules.md) | **Normative**, with rule data and corpus |
| [`05-index.md`](05-index.md) | Draft — derived from the reference implementation |
| [`06-lockfile.md`](06-lockfile.md) | **Normative**, with L4 conformance |
| [`07-conformance.md`](07-conformance.md) | **Normative** |
| [`09-signatures.md`](09-signatures.md) | **Normative**, with L5 conformance |
| [`10-attestations.md`](10-attestations.md) | **Normative** for §10.1–10.5 and §10.7–10.8, with L5 conformance; §10.6 reserved |
| [`11-advisories.md`](11-advisories.md) | **Normative**, with L5 conformance |

"Draft" means the behaviour is real and implemented, but this document has not
yet been reviewed as the authority. Where a draft document and the reference
implementation disagree, the implementation is currently correct and the
document is a defect. That asymmetry ends when a document is marked normative.

Marking a document normative requires: a corpus that exercises each stated
rule, and at least one implementation that passes it without special-casing.

## 0.4 Conventions

MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as defined in RFC 2119.

Byte values are written as `0x00`. Digests are lowercase hex. Paths are
POSIX-style with `/` separators regardless of host platform.

## 0.5 Versioning

This specification versions independently of any implementation, and
deliberately more slowly.

- **Patch** — editorial only.
- **Minor** — new rules, new optional fields, new corpus cases; backwards
  compatible for readers.
- **Major** — a change that makes a previously conformant implementation
  non-conformant. Requires a migration note.

Rule identifiers are permanent and are **never reused**, including after
withdrawal. An identifier appearing in a suppression file written three years
ago must never silently come to mean something else.

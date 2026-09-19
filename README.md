<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# agtmls-spec

**The normative specification for AgtMLS agent skills, and the conformance
corpus that proves an implementation follows it.**

This repository contains no runtime code. It exists because four surfaces —
a CLI, a language server, an MCP server and a WASM module — will need to agree
about what a skill *is*, what its content address is, and what counts as a
finding. Without a single normative source and a shared corpus, that agreement
decays quietly: a payload one implementation blocks becomes one another calls
clean, and nobody notices until it matters.

## What is normative here

| Document | Defines |
| :--- | :--- |
| [`spec/01-skill.md`](spec/01-skill.md) | `SKILL.md`: frontmatter, body budget, progressive disclosure |
| [`spec/02-metadata.md`](spec/02-metadata.md) | `metadata.json`: `safety_policy`, `bundle`, `maturity` |
| [`spec/03-integrity.md`](spec/03-integrity.md) | The skill digest algorithm |
| [`spec/04-rules.md`](spec/04-rules.md) | Analyzer rule identifiers, severities, categories |
| [`spec/05-index.md`](spec/05-index.md) | `index.json` registry format |
| [`spec/06-lockfile.md`](spec/06-lockfile.md) | `.agtmls/manifest.json` install lockfile |
| [`spec/07-conformance.md`](spec/07-conformance.md) | How an implementation claims a conformance level |

Machine-readable schemas live in [`schema/`](schema/). Rules are **data**, not
code: [`rules/`](rules/) holds one TOML file per rule, loaded identically by
every implementation, so adding a rule never means writing the same regex
twice in two languages.

## The corpus is the contract

| Corpus | Cases | Proves |
| :--- | ---: | :--- |
| [`corpus/security/`](corpus/security/) | 16 | The analyzer detects what it claims, and stays quiet on benign input |
| [`corpus/digest/`](corpus/digest/) | 12 | Two implementations compute the same content address |
| [`corpus/frontmatter/`](corpus/frontmatter/) | 10 | Parsers agree on the same inputs |

A corpus case is a data manifest, not a directory of fixture files. Two
reasons: a fixture with deliberately malformed JSON or an unsigned shell
script would fail the host repository's own validators, and a
language-independent manifest can be replayed against any implementation,
including ones that do not exist yet.

The security corpus deliberately includes **evasion variants** — a payload
split across a newline, alternate invisible-character channels, malicious code
in a non-markdown file. Testing each rule against one canonical string proves
the regex compiles and nothing else; the AgtMLS analyzer passed exactly that
kind of test while three independent evasions walked through it.

## Conformance levels

| Level | Name | Requires |
| :--- | :--- | :--- |
| **L1** | Reader | Parses skills and index correctly (`frontmatter`, `index`) |
| **L2** | Verifier | L1, plus digests match the normative vectors (`digest`) |
| **L3** | Analyzer | L2, plus the full security corpus including evasions |
| **L4** | Registry | L3, plus install, lockfile and verification semantics |

An implementation publishes `conformance.json` declaring its level. The runner
recomputes it. **A claimed level that differs from the computed level is a
build failure** — the point of a conformance claim is that it is checked.

## Implementations

| Implementation | Language | Level |
| :--- | :--- | :--- |
| [`agtmls`](https://github.com/sebastienrousseau/agtmls) | Python (stdlib only) | L3 |
| [`agtmls-core`](https://github.com/sebastienrousseau/agtmls-core) | Rust | L3 |

Both are replayed against this corpus in CI. **If they disagree, both builds
fail.** That is the mechanism that keeps two implementations from becoming two
products.

## Versioning

This specification versions independently of any implementation, and
deliberately more slowly. Implementations declare a compatible range.

- **Patch** — editorial only; no behaviour change.
- **Minor** — new rules, new optional fields, new corpus cases. Backwards
  compatible for readers.
- **Major** — a change that makes a previously conformant implementation
  non-conformant. Requires a migration note in `spec/`.

Rule identifiers are permanent. A withdrawn rule is marked withdrawn and its
identifier is **never reused**.

## Licence

Apache-2.0 OR MIT.

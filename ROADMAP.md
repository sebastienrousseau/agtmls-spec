<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Roadmap

The measure here is not how many rules exist. It is how many of them have a
corpus case that would fail without them.

## Now

Five of eight documents are normative. `01-skill`, `02-metadata` and `05-index`
are drafts that say plainly that where they and the reference implementation
disagree, **the implementation is correct and the document is the defect**.

## Next

- **Promote the three drafts.** Each needs a corpus exercising every rule it
  states, and an implementation passing without special-casing. That is the
  bar, and it is why they are not normative yet.
- **Widen the security corpus.** Base64 and hex-encoded payloads, entropy,
  and frontmatter that grants tools no runtime defines.
- **Conformance levels beyond L5.** Nothing yet implements install semantics
  end to end in two languages, and the audit predicate (§10.6) has no
  emitter.

## Not planned

- **Routing.** How an agent decides to load a skill is a model behaviour, not
  a wire format, and freezing a guess into a specification would be worse than
  saying nothing.

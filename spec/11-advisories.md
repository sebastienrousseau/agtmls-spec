<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 11. Advisories and Revocation

**Status:** draft — no implementation consults advisories yet. It becomes
normative when one passes [`corpus/advisories/`](../corpus/advisories/)
without special-casing, per [00-overview.md §0.3](00-overview.md).

## 11.1 Purpose

A signature proves a skill was published; it cannot say the skill should no
longer be used. An advisory can. `verify` checks installed skills against a
signed feed and reports any that are revoked, so a compromised release is
caught in every repository that installed it, not only in new installs.

## 11.2 Feed

`advisories.json` is an object with `schema_version` and an `advisories`
array of [OSV](https://ossf.github.io/osv-schema/) records, so existing
vulnerability tooling can read it. Each record MUST have:

- `id`: `AGT-ADV-<YYYY>-<NNN>`, unique and never reused;
- `modified`, and SHOULD have `published`: RFC 3339 UTC timestamps;
- `affected`: one or more entries whose `package.ecosystem` is `AgtMLS`,
  `package.name` is the skill name, and `ecosystem_specific.digests` lists
  the revoked skill digests (§3.10 presentation, `sha256:<hex>`).

OSV has no notion of a content digest, which is why the digests are
ecosystem-specific. A verifier MUST match on digest and MUST NOT match on
name or version: a later, fixed release of the same skill has a different
digest and is not revoked (vector `same-name-other-digest-is-not-revoked`).

An advisory with OSV's `withdrawn` timestamp revokes nothing.

## 11.3 Signing and distribution

The feed is signed as the index is (§9.2), in `advisories.json.sig`, under
the namespace `agtmls-advisory@v1`. An unverified feed MUST NOT be consulted
at all, including for the revocations it contains: a feed anyone can edit is
a way to make a verifier distrust any skill.

The feed ships with the registry, so `verify` works offline. A verifier MAY
offer `--refresh`, which fetches the feed from a URL fixed in the
implementation, only when asked. The fetched feed MUST verify before it
replaces the local one, and a failed refresh MUST leave the local feed as it
was.

## 11.4 Outcomes and exit codes

For each installed skill in the lockfile, a verifier reports every advisory,
not withdrawn, whose digests include the skill's recorded digest.

Exit code `6` (`REVOKED`, §9.5) means at least one installed digest is
revoked, and the output MUST name the advisory ids. When more than one
failure applies, the exit code is the first of:

| Order | Code | Why it comes first |
| ---: | ---: | :--- |
| 1 | `5` | A feed or index that does not verify cannot support any conclusion. |
| 2 | `3` | What is installed is not what was published. |
| 3 | `6` | What was published is installed, and it is revoked. |
| 4 | `4` | A signature was required and is absent. |

## 11.5 Vectors

[`corpus/advisories/cases.json`](../corpus/advisories/cases.json) pairs one
signed feed with six lockfiles: a revoked digest, a withdrawn advisory, the
same skill name at another digest, nothing listed, a feed signed under the
wrong namespace, and no signature. The signing key's private half was
discarded. `conformance/validate-advisories.py` checks the feed's shape and
evaluates each case, signature first, in CI.

<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 7. Conformance

**Status:** normative.

## 7.1 Levels

| Level | Name | Requires |
| :--- | :--- | :--- |
| **L1** | Reader | Parses `SKILL.md` frontmatter and `index.json` per `corpus/frontmatter/` and `corpus/index/` |
| **L2** | Verifier | L1, and reproduces every vector in `corpus/digest/` exactly |
| **L3** | Analyzer | L2, and passes `corpus/security/` including its evasion variants, with no false positive on benign cases |
| **L4** | Registry | L3, and implements install, lockfile and verification semantics |

## 7.2 Claiming a level

An implementation MUST publish `conformance.json`:

```json
{
  "implementation": "agtmls-core",
  "version": "0.0.1",
  "spec_version": "0.1.0",
  "claimed_level": "L3"
}
```

The runner recomputes the level from the corpus results. **A claimed level
that differs from the computed level MUST fail the build.** A conformance
claim that is not checked is marketing.

## 7.3 The runner must not skip

An implementation's conformance suite MUST fail, not skip, when the corpus is
unavailable.

A suite that skips reports green while proving nothing, and it reports green
in exactly the situation where you most need the signal: a misconfigured CI
job, a missing checkout, a renamed path. This is not a hypothetical failure
mode — during development of `agtmls-core` the suite was briefly placed where
the build system did not collect it, and reported `ok. 0 passed` while
verifying nothing at all.

## 7.4 Differential conformance

Where two or more implementations exist, CI MUST run them against the same
corpus and compare their outputs to **each other**, not only to the expected
values.

Two implementations can each pass their own test suite and still disagree — a
divergence neither can detect from the inside. The differential pass is the
only thing that catches it.

Every defect listed in §4.6 was found this way, by running a second
implementation against rule data the first had produced and passed.

## 7.5 Minimum evidence

To claim a level, an implementation MUST publish:

1. `conformance.json`;
2. CI logs, or an attestation, showing the runner passing at that level;
3. the `spec_version` range it targets.

An implementation that special-cases a corpus input to make it pass is not
conformant, and the corpus SHOULD be extended with a variant that defeats the
special case. Rules are data precisely so that "make the test pass" and "fix
the rule" are the same action.

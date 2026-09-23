<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 4. Analysis Rules

**Status:** normative.
**Rule data:** [`rules/`](../rules/). **Corpus:** [`corpus/security/`](../corpus/security/).

## 4.1 Rules are data

A rule MUST be expressed as a TOML file in `rules/`, loaded identically by
every implementation. An implementation MUST NOT hard-code a pattern that
exists in `rules/`.

This is the whole design. With patterns compiled into each implementation,
adding a rule means writing the same regex twice and hoping the two engines
agree about `\s`, case folding and greediness. They do not, reliably — see 4.6.

## 4.2 Identifiers

`AGT-<CLASS>-<NNN>`, where `<NNN>` is zero-padded to three digits.

| Class | Meaning | Default severity |
| :--- | :--- | :--- |
| `STEG` | Hidden or invisible code points | CRITICAL |
| `INJ` | Prompt injection, jailbreak | HIGH |
| `EXEC` | Unsafe execution, credential access | HIGH |
| `EXFIL` | Data exfiltration channels | HIGH |
| `CAP` | Capability escalation against declared policy | HIGH |
| `POLICY` | Policy honesty and attestation | HIGH / MEDIUM |
| `SCAN` | Analyzer limits | MEDIUM |

Identifiers are permanent. A withdrawn rule MUST be marked `withdrawn = true`
and its identifier MUST NOT be reused.

## 4.3 Matching scope

| `scope` | Meaning |
| :--- | :--- |
| `normalised` | Matched against the document with every whitespace run collapsed to a single space. **The default.** |
| `line` | Matched per line. |
| `raw` | Matched against the decoded content unchanged. |

A pattern rule SHOULD use `normalised`. Line-scoped matching is trivially
evaded: an attacker inserts a newline mid-phrase and every line-scoped rule
misses it. The reference implementation shipped with all rules line-scoped,
and a payload split across two lines passed a strict audit cleanly.

Findings MUST still report a **source line number**, not an offset into the
normalised text. An implementation SHOULD build the mapping lazily, once a
pattern has matched, since almost every file is clean.

## 4.4 Examples are executable

A rule MAY declare `[[true_positive]]` and `[[false_positive]]` entries. An
implementation MUST execute them when loading the rule set, and MUST refuse to
load a rule that does not match its own true positive or that does match its
own false positive.

A pattern that has never been run against a known input is an assertion, not a
control. Both defects in 4.6 were found this way and by nothing else.

## 4.5 When no false positive is acceptable

Some rules should prefer the false positive. A rule MAY declare:

```toml
false_positive_policy = "none-acceptable"
```

and MUST accompany it with a comment explaining why.

`AGT-INJ-001` is the worked example. It matches any instruction-override
phrase, including prose *describing* one. Excluding prose would require
negation detection, and negation detection is inverted by writing "never
ignore all previous instructions". The correct escape hatch is a digest-keyed
suppression — reviewable, scoped, visible in a diff — not a weaker pattern,
which is none of those things.

## 4.6 Portability requirements

These are not stylistic. Each corresponds to a defect found by running a
second implementation against the same rule data.

1. **Case-insensitivity MUST be expressed inline as `(?i)`**, never as a host
   language compile flag. A flag does not survive export to shared data: the
   Python implementation compiled with `re.IGNORECASE`, the exported pattern
   carried no flag, and the Rust implementation matched case-sensitively.
   `IGNORE ALL PREVIOUS INSTRUCTIONS` would have passed.

2. **Patterns MUST be stored in TOML *literal* strings** (`'''…'''`), where a
   backslash is literal. Escaping as for a basic string doubles every
   backslash, so `\s` ships as `\\s` and the pattern matches nothing at all —
   silently, while every self-test that was never run reports green.

3. **Patterns MUST NOT rely on backtracking.** Rust's `regex` has no
   backtracking by design; a pattern requiring it behaves differently or
   refuses to compile. Avoid backreferences and lookaround.

## 4.7 Severity and exit behaviour

An implementation MUST fail a strict audit on CRITICAL or HIGH. MEDIUM and LOW
MUST NOT fail by default, and MUST fail under a strict flag.

## 4.8 Structural rules

Rules whose logic is not a pattern (`AGT-STEG-001`, `AGT-CAP-001`,
`AGT-POLICY-*`, `AGT-SCAN-001`) MUST still be declared in `rules/` with
`kind = "structural"`, so the rule set can be enumerated from data alone
without reading any implementation's source.

## 4.9 Fail closed

`AGT-POLICY-001` and `AGT-POLICY-002` exist because the reference
implementation returned no findings when `metadata.json` was missing or
unparseable. Deleting the file that declares the safety policy was therefore
the cheapest way to pass every policy check.

An implementation MUST treat absent or unreadable policy as a HIGH finding.
Absence of evidence is not evidence of safety.

## 4.10 `AGT-CAP-001`: reading `allowed-tools`

`AGT-CAP-001` compares the tools a `SKILL.md` frontmatter grants with the
capabilities `metadata.json` `safety_policy` admits to. Every implementation
MUST read the grant the same way, or the rule fires in one and not another.

**Locating the field.** The value is the remainder of the first frontmatter
line that begins `allowed-tools:`, with any leading spaces and tabs removed.
A skill with no frontmatter, or no such line, grants no tools.

**Tokenising.** An implementation MUST split the value into tools exactly as
this pattern's successive non-overlapping matches do, left to right:

```text
[^\s,()'"\[\]]+(?:\([^)]*\))?
```

where `\s` includes `0x1C`–`0x1F` (as Python's does; add them explicitly in
an engine whose `\s` does not). In words:

1. Whitespace **and** commas separate tools. The Agent Skills form is
   space-separated — `allowed-tools: "Read Glob Bash"` — and MUST yield
   `Read`, `Glob`, `Bash`. A comma-separated or mixed value yields the same.
2. Single quotes, double quotes and YAML flow-list brackets are never part of
   a tool: `allowed-tools: [Bash, 'Read']` yields `Bash`, `Read`.
3. A tool MAY carry a parenthesised specifier, which stays part of its token
   even when it contains spaces: `Bash(git log:*)` is one tool. An opening
   parenthesis with no closing one ends the token before it.

**Capability lookup.** A tool's capability is looked up by the part of the
token before its first `(`, so `Bash(git log:*)` narrows `Bash` and still
grants `executes_commands`. Tools absent from this table grant nothing:

| Tool | Capability | Granted when `safety_policy` has |
| :--- | :--- | :--- |
| `Bash`, `BashOutput`, `KillShell` | `executes_commands` | `executes_commands: true` |
| `Write`, `Edit`, `NotebookEdit` | `writes_files` | `writes_files: true` |
| `WebFetch`, `WebSearch` | `network_access` | `network_access` of `optional` or `required` |

Each granted tool whose capability the policy does not grant is one
`AGT-CAP-001` finding.

Splitting on commas alone is the defect this section exists to prevent. It
returned `"Read Glob Bash"` as a single tool of that name, which is in no
table and grants nothing, so the rule could not fire on any skill written in
the spec's own form. Both implementations passed the corpus while it
contained only a comma-separated case; `corpus/security/` now carries the
space-separated, quoted, flow-list and scoped forms.

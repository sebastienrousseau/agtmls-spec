<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# Rule definitions

One TOML file per rule. Every implementation loads this directory, so adding a
rule means adding a file and a corpus case — never writing the same pattern
twice in two languages and hoping they stay equivalent.

## Required fields

| Field | Meaning |
| :--- | :--- |
| `id` | Stable identifier, `AGT-<CLASS>-<NNN>`. Permanent; never reused. |
| `category` | Finding category, e.g. `unsafe_execution`. |
| `severity` | `low` \| `medium` \| `high` \| `critical`. |
| `title` | Short human title; becomes the finding message. |
| `pattern` | Regex source, in a TOML **literal** string (`'''…'''`) so backslashes stay literal. Omit for structural rules. |
| `scope` | `normalised` (default), `line`, or `raw`. |
| `applies_to` | File selectors, plus the literal `executable`. |

## Examples are executable, not decorative

`[[true_positive]]` and `[[false_positive]]` entries are run against the
pattern **at load time**. A rule that does not match its own true positive, or
that matches its own false positive, is rejected — the rule set fails to load
rather than shipping a pattern nobody executed.

This is not theoretical. Both defects found while writing these files were
found this way:

- `AGT-EXEC-001` matched prose *warning against* `curl … | bash`. Requiring an
  actual fetch target (a URL or a variable) separates the instruction from the
  warning. A rule that flags its own documentation is a rule that gets
  suppressed wholesale.
- A generator escaped backslashes as if for a TOML *basic* string, so every
  pattern shipped as `\\s` instead of `\s` and matched nothing at all.

## When no false positive is acceptable

Some rules should prefer the false positive. `AGT-INJ-001` matches any
instruction-override phrase, including prose describing one, because the
alternative is negation detection — and negation detection is inverted by
writing "never ignore all previous instructions".

Declare that stance explicitly:

```toml
false_positive_policy = "none-acceptable"
```

with a comment saying why. The escape hatch for a legitimate hit is a
digest-keyed suppression in `.agtmls-audit-ignore`: reviewable, scoped, and
visible in a diff. Weakening the pattern is none of those things.

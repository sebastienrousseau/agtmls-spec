<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 2. Skill Metadata

**Status:** draft — derived from the reference implementation, not yet
reviewed as the authority.

metadata.json: `bundle`, `version`, `owner`, `maturity`, `supported_agents`, `required_tools`, `safety_policy`. The `safety_policy` block is what `AGT-CAP-001` and `AGT-POLICY-*` check against, and what `allowed-tools` frontmatter is derived from.

`allowed-tools` is space- or comma-separated (`allowed-tools: "Read Glob Bash"`);
how it is tokenised, and which tools grant which capability, is normative in
[04-rules.md §4.10](04-rules.md#410-agt-cap-001-reading-allowed-tools).

Where this document and the reference implementation disagree, **the
implementation is currently correct and this document is the defect**. That
asymmetry ends when this document is marked normative, which requires a corpus
exercising each stated rule and an implementation passing it without
special-casing. See [00-overview.md §0.3](00-overview.md).

<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 1. Skill Format

**Status:** draft — derived from the reference implementation, not yet
reviewed as the authority.

SKILL.md: YAML frontmatter followed by Markdown. Normative content is pending review; the authority today is `validate-skills.py` and `validate-skill-metadata.py` in the reference implementation, plus `corpus/frontmatter/`.

Where this document and the reference implementation disagree, **the
implementation is currently correct and this document is the defect**. That
asymmetry ends when this document is marked normative, which requires a corpus
exercising each stated rule and an implementation passing it without
special-casing. See [00-overview.md §0.3](00-overview.md).

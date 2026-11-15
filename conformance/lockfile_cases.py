# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""L4 lockfile cases judged absolutely rather than by agreement (chapter 6).

Kept beside run.py, which imports them, so the runner stays within the
portfolio's 500-line file ceiling.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path


def escaping_lockfile_tree(root: Path, skill: Path, digest: str) -> Path:
    """A clean install whose one lockfile entry names a directory outside the
    skills directory, `../../outside`, holding a real skill with its true
    digest. Followed, it verifies clean (exit 0); refused, it is unreadable."""
    tree = root / "escaping"
    (tree / ".claude" / "skills").mkdir(parents=True)
    shutil.copytree(skill, tree / "outside")
    lock = {
        "schema_version": 1, "spec_version": "0.1.0", "installed_at": "2026-01-01T00:00:00Z",
        "source": {"registry": "https://example.com", "registry_version": "0.0.0"}, "mode": "copy",
        "skills": [{"name": skill.name, "integrity": digest, "path": "../../outside", "agents": ["claude"]}],
    }
    (tree / ".agtmls").mkdir()
    (tree / ".agtmls" / "manifest.json").write_text(json.dumps(lock), encoding="utf-8")
    return tree


def escaping_lockfile_case(impls: list, fixture: Path) -> list[str]:
    """6.2 and 6.5: a lockfile entry that is not a single directory name makes
    the lockfile unreadable, exit 3. Checked absolutely, not by agreement:
    two implementations that both follow the path agree on exit 0."""
    skills = sorted(p for p in (fixture / ".claude" / "skills").iterdir() if (p / "SKILL.md").is_file())
    if not skills:
        return ["no intact skill in the install fixture to build the escaping-lockfile case from"]
    with tempfile.TemporaryDirectory(prefix="agtmls-escape-") as raw:
        tree = escaping_lockfile_tree(Path(raw), skills[0], impls[0].digest(skills[0]))
        codes = {impl.name: impl.verify_exit(tree, "claude") for impl in impls}
    wrong = {name: code for name, code in codes.items() if code != 3}
    return [f"escaping lockfile path: expected exit 3, got {wrong}"] if wrong else []

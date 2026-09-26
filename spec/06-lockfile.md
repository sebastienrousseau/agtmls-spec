<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 6. Install Lockfile

**Status:** normative.
**Schema:** [`schema/lockfile.schema.json`](../schema/lockfile.schema.json).
**Conformance:** L4, exercised by `conformance/run.py`, which builds an
install, tampers with it, and requires every implementation to agree about
what is wrong with it.

## 6.1 Purpose

`agtmls install` writes `.agtmls/manifest.json` into the target repository,
recording what was installed and what it hashed to. Without it there is no
answer to "is what I have what you published?", and the registry is a
decorated `ln -s`.

## 6.2 Format

```json
{
  "schema_version": 1,
  "spec_version": "0.1.0",
  "installed_at": "2026-09-19T10:37:10Z",
  "source": {
    "registry": "https://github.com/sebastienrousseau/agtmls",
    "registry_version": "0.0.6"
  },
  "mode": "symlink",
  "skills": [
    {
      "name": "cross-language-port",
      "integrity": "sha256:8a9bee28a846d03a01f8432a4b06d0679b40b3ee68c18a765a1f08a3ec511879",
      "path": "cross-language-port",
      "executable_files": ["harness/port-check.sh", "harness/golden-diff.sh"],
      "agents": ["claude", "codex"]
    }
  ]
}
```

`mode` is `symlink` or `copy`. `path` is relative to the agent's skills
directory (`.claude/skills/`, `.codex/skills/`, ...). `executable_files`
records the mode bits that [`03-integrity.md`](03-integrity.md) deliberately
excludes from the digest, so a lost executable bit can be repaired without
being mistaken for tampering.

### One lockfile, several agents

A target holds one lockfile, and more than one agent may be installed in it.
`agents` names the native agents whose skills directory holds the entry. An
entry is one skill at one digest: two agents holding different versions of a
skill have one entry each.

- Installing for an agent MUST change only that agent's membership: remove
  it from every entry, then add it to the entries it installed. An entry no
  agent holds is dropped.
- Uninstalling an agent MUST remove only that agent's membership, except for
  a skill it left in place (6.6), and MUST remove the lockfile only when no
  entry names any agent.
- An entry without `agents` was written before the field existed. It MUST be
  treated as serving every agent. An implementation that rewrites the
  lockfile SHOULD resolve it to the agents whose skills directory holds that
  skill.

Rewriting the whole lockfile on each install made the second agent's install
erase the first agent's record, so the first agent's `verify` failed on a
tree nobody had touched.

## 6.3 Verification

`agtmls verify <agent>` MUST recompute the digest of each entry serving that
agent and compare it with `integrity`. Entries serving only other agents MUST
NOT be reported: they describe another directory.

| Outcome | Meaning |
| :--- | :--- |
| Match | Installed content is what was published. |
| Mismatch | Local edit, or tampering. MUST be reported; MUST NOT be silently repaired. |
| Missing | The skill was removed after install. |
| Not in lockfile | Present but unmanaged. Reported, never deleted. |

An implementation MUST NOT delete anything it did not record installing.

## 6.4 Upgrade

`agtmls upgrade` compares lockfile digests with the registry index and
reinstalls only where they differ. This is the capability the current
denormalised version field cannot provide: every skill carries the registry
version, so "what changed?" has no answer short of diffing every file.

## 6.5 Exit codes

An implementation MUST distinguish an integrity failure from an ordinary
error:

| Code | Meaning |
| ---: | :--- |
| `0` | Every recorded skill matches. Unmanaged skills may be present. |
| `1` | An error unrelated to integrity. |
| `2` | Usage error. |
| `3` | `INTEGRITY_FAILURE`: a recorded skill is modified or missing, or the lockfile is unreadable. |

Collapsing this into `0`/`1` makes "the tool broke" and "your install has been
altered" indistinguishable to a calling script, which is the one distinction
the lockfile exists to provide.

## 6.6 Verification is not repair

An implementation MUST NOT silently repair a mismatch.

Rewriting a skill whose digest moved would destroy a local edit, and would
hide tampering behind exactly the same behaviour. Report; let a human decide.

An implementation MUST NOT delete a skill it has no record of installing. An
unmanaged skill is reported and is **not** an integrity failure: a skill the
tool did not install is not evidence that what it did install was altered.

## 6.7 Verify before installing, not after

An implementation SHOULD verify its **source** registry against the index
before copying anything, and MUST refuse with `3` on a mismatch.

Copying a tampered skill into a consumer's repository and then reporting it is
not a control. The refusal MUST leave the target untouched.

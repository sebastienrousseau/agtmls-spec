<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 3. Skill Integrity

**Status:** normative.
**Test vectors:** [`corpus/digest/cases.json`](../corpus/digest/cases.json).

Every skill has a **content address**: a digest over its files that is
identical wherever the skill came from. This is the foundation for install
verification, per-skill versioning, upgrade diffing and tamper detection.
Nothing else in this specification matters as much, because without it a
registry cannot answer the only question a consumer actually has — *is what I
have what you published?*

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119.

## 3.1 Algorithm

```
skill_digest(dir):
    entries = []
    for each regular file f in dir, recursively:
        if excluded(f): continue
        entries.append( (relpath(f, dir), SHA256(contents(f))) )

    sort entries by the UTF-8 encoded bytes of relpath

    h = SHA256()
    for (relpath, content_hash) in entries:
        h.update( utf8(relpath) )
        h.update( 0x00 )
        h.update( content_hash )        # 32 raw bytes, not hex
        h.update( 0x00 )

    return "sha256:" + hex(h.digest())
```

`relpath` MUST use `/` as the separator on every platform.

## 3.2 Why a manifest and not an archive

Hashing a tarball would be simpler and wrong. A tarball digest depends on the
archive format, member ordering, stored mtimes, uid/gid and padding — none of
which are properties of the skill. The same skill would produce different
digests from a git clone, an extracted wheel and a release tarball, so the
digest could never be used to verify an install.

Hashing the manifest binds exactly what the skill *is*: which files exist, at
which paths, with which contents.

## 3.3 Exclusions

An implementation MUST exclude:

| Exclusion | Reason |
| :--- | :--- |
| `.DS_Store`, `Thumbs.db` | OS debris. A digest that moves because macOS wrote a file is a false integrity failure. |
| `__pycache__/`, `.git/`, `.agtmls/`, `node_modules/`, `.venv/` | Build, VCS and install caches. Not authored content. |
| `*.pyc`, `*.pyo`, `*.swp` | Derived or editor artefacts. |
| Symlinks | See 3.5. |

Directory exclusions apply to any path component, not only the top level.

## 3.4 Mode bits are not hashed

An implementation MUST NOT include file permissions in the digest.

The executable bit does not survive every transport: zip archives on Windows,
some CI artifact round-trips, and `pip install` from an sdist can all drop it.
A digest that changes according to how a file arrived cannot verify an
install, which is the one thing it exists to do.

Modes are recorded separately in the lockfile ([`06-lockfile.md`](06-lockfile.md)),
where they are advisory and can be repaired without invalidating identity.

## 3.5 Symlinks

An implementation MUST NOT follow symlinks, and MUST NOT include them in the
manifest. It SHOULD report them to the caller.

Following a symlink makes the digest depend on a file outside the skill, which
is both non-reproducible and a path-traversal vector: a skill containing
`notes.md -> ~/.ssh/id_ed25519` would otherwise pull a private key into its
own identity, and into anything derived from it.

A skill that requires a symlink is not portable and MUST NOT be published.

## 3.6 Empty directories

An empty directory MUST NOT contribute to the digest. A directory is its
files. Git cannot represent an empty directory anyway, so including one would
make the digest depend on the transport — the failure mode 3.2 exists to
avoid.

## 3.7 Ordering

Entries MUST be sorted by the **UTF-8 encoded bytes** of the relative path.

Sorting by decoded string under a locale-aware collation is a defect: the same
tree would digest differently under `LANG=en_US.UTF-8` and `LANG=C`, and the
difference would appear only for skills containing non-ASCII filenames — that
is, rarely, and in the field.

## 3.8 Separators

The `0x00` bytes after the path and after the content hash are required.
Without them the concatenation is ambiguous: a file `ab` with content hashing
to `X` and a file `a` with content hashing to `bX` would produce identical
input. `0x00` cannot appear in a UTF-8 encoded path, so it is an unambiguous
terminator.

The content hash MUST be written as its **32 raw bytes**, not as 64 hex
characters. Both are unambiguous given the separators; the raw form is
specified so implementations do not differ.

## 3.9 Worked example

A skill containing exactly:

```
SKILL.md        (contents: "# S\n")
reference.md    (contents: "ref\n")
```

```
SHA256("# S\n")  = 9d8f...          (see corpus/digest/cases.json)
SHA256("ref\n")  = 2c9a...

h = SHA256(
      "SKILL.md"     || 0x00 || <32 bytes> || 0x00 ||
      "reference.md" || 0x00 || <32 bytes> || 0x00
    )
```

Note `SKILL.md` sorts before `reference.md`: `S` (0x53) precedes `r` (0x72) in
byte order. Under a case-insensitive collation it would sort *after*, which is
exactly the divergence 3.7 forbids. The corpus contains this case specifically.

## 3.10 Presentation

A digest MUST be rendered as `sha256:` followed by 64 lowercase hex
characters. Implementations MUST accept only lowercase on parse; uppercase
would allow two spellings of the same value and defeat string comparison.

## 3.11 Conformance

An L2 implementation MUST reproduce every digest in
[`corpus/digest/cases.json`](../corpus/digest/cases.json) exactly.

The corpus includes cases that isolate each rule above: byte-order sorting,
excluded files, a symlink, an empty directory, a non-ASCII filename, and the
`SKILL.md` / `reference.md` ordering trap. An implementation that passes only
the trivial case has not been tested.

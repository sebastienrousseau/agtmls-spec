<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau -->
<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# 9. Index Signatures

**Status:** normative. **Conformance:** L5: both reference implementations
reproduce every vector in [`corpus/signatures/`](../corpus/signatures/), and
`conformance/run.py` compares their verdicts and exit codes with each other.

## 9.1 Purpose

A skill's `integrity` digest ([03-integrity.md](03-integrity.md)) proves the
installed files are the files the index names. It does not prove the index
came from the registry: anyone who can serve an `index.json` can serve digests
that match their own files. A signature over the index closes that gap, and
it must be checkable offline, because the local tier never reaches the
network.

## 9.2 What is signed

The signature covers the exact bytes of `index.json` as published. There is no
canonicalisation step: the bytes a verifier reads are the bytes that were
signed, and a formatter that rewrites whitespace invalidates the signature,
which is the intended behaviour.

The signature is an OpenSSH `SSHSIG` signature, armored, in a sibling file
`index.json.sig`, made with:

```
ssh-keygen -Y sign -f <key> -n agtmls-index@v1 index.json
```

The namespace `agtmls-index@v1` MUST be used for index signatures and for
nothing else. A signature made by the right key for another purpose is not an
index signature (vector `wrong-namespace`).

## 9.3 Trusted keys

Trusted keys are listed in an `allowed_signers` file in the format
`ssh-keygen(1)` defines under ALLOWED SIGNERS, with the principal
`agtmls-release` and the option `namespaces="agtmls-index@v1"`. A verifier
MUST take this file from a source it already trusts, such as the installed
package or a pinned checkout, and MUST NOT take it from the same location as
the index it is verifying.

## 9.4 Rotation

A key is retired by giving its line a `valid-before` date and adding the new
key with a `valid-after` date. The retired line MUST stay: it is what lets an
index signed before rotation still verify (vector
`previous-key-before-rotation`), while a signature by the retired key after
its window fails (`previous-key-after-rotation`). `valid-after` is enforced as
strictly as `valid-before` (`current-key-before-its-window`).

Validity is judged at a verification time. A verifier SHOULD use the current
time; the vectors each name a fixed `verify_time` (`YYYYMMDD`) so that they do
not expire.

## 9.5 Verification and exit codes

A verifier MUST refuse to treat an index as signed unless all of these hold:
the signature file exists, it verifies under `agtmls-index@v1`, the signer is
listed for the principal `agtmls-release`, and the verification time is inside
that key's window. This is exactly

```
ssh-keygen -Y verify -f allowed_signers -I agtmls-release \
    -n agtmls-index@v1 -s index.json.sig < index.json
```

and an implementation MAY delegate to it.

Extending [06-lockfile.md §6.5](06-lockfile.md):

| Code | Meaning |
| ---: | :--- |
| `4` | `UNSIGNED`: no signature was found where one was required. |
| `5` | `BAD_SIGNATURE`: a signature exists and does not verify: tampered bytes, an unknown signer, the wrong namespace, or a key outside its window. |
| `6` | `REVOKED`: reserved for [11-advisories](11-advisories.md); a verified index names a revoked digest. |

`4` and `5` MUST be distinct: "nobody signed this" and "someone signed
something else" call for different responses, and collapsing them is the
same mistake §6.5 exists to prevent.

## 9.6 Vectors

[`corpus/signatures/cases.json`](../corpus/signatures/cases.json) lists eight
cases over one fixture index, three keys and one `allowed_signers` file. The
keys were generated for the vectors and their private halves discarded, so no
secret is in this repository and no one can add a vector signed by them.
`conformance/validate-signatures.py` checks every case against
`ssh-keygen -Y verify`, so the vectors cannot drift from the tool they
describe.

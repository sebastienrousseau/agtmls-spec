#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Replay the conformance corpus against one or more implementations.

Usage:
    conformance/run.py --python /path/to/agtmls
    conformance/run.py --rust   /path/to/agtmls-rs
    conformance/run.py --python /path/to/agtmls --rust /path/to/agtmls-rs

With two or more implementations it additionally runs a **differential** pass:
every implementation must produce the same digest for the same input. Two
implementations that each pass their own tests but disagree with each other is
the failure this repository exists to prevent, and it is not detectable from
inside either one.

Exit codes:
    0  every requested level passed
    1  a conformance failure
    2  usage error, or an implementation could not be invoked
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SPEC_ROOT = Path(__file__).resolve().parent.parent


class Implementation:
    """One implementation under test."""

    def __init__(self, name: str, kind: str, location: Path) -> None:
        self.name = name
        self.kind = kind
        self.location = location

    def verify_install(self, target: Path, agent: str) -> tuple[int, set[tuple[str, str]]]:
        """(exit code, {(skill, status)}) for an installed tree."""
        if self.kind == "python":
            argv = [sys.executable, str(self.location / "scripts" / "agtmls.py"),
                    "verify", agent, "--target", str(target), "--json"]
        else:
            argv = [str(self.location), "verify", str(target), "--agent", agent, "--json"]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{self.name}: verify produced no JSON: {exc}\n{proc.stdout[:400]}")
        problems = {
            (p.get("skill") or p.get("name", ""), p["status"])
            for p in payload.get("problems", [])
        }
        return proc.returncode, problems

    def audit(self, path: Path, rules: Path) -> set[str]:
        """Rule identifiers this implementation reports for `path`."""
        if self.kind == "python":
            proc = subprocess.run(
                [sys.executable, str(self.location / "scripts" / "audit-skill.py"),
                 str(path), "--strict", "--format", "json"],
                capture_output=True, text=True, check=False,
            )
        else:
            proc = subprocess.run(
                [str(self.location), "audit", str(path), "--rules", str(rules), "--json"],
                capture_output=True, text=True, check=False,
            )
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{self.name}: audit produced no JSON: {exc}\n{proc.stdout[:400]}")
        return {f["rule"] for f in payload.get("findings", [])}

    def digest(self, path: Path) -> str:
        if self.kind == "python":
            code = (
                "import sys; sys.path.insert(0, r'%s');"
                "from _lib.digest import skill_digest; from pathlib import Path;"
                "print(skill_digest(Path(sys.argv[1])))" % (self.location / "scripts")
            )
            proc = subprocess.run(
                [sys.executable, "-c", code, str(path)],
                capture_output=True, text=True, check=False,
            )
        else:
            proc = subprocess.run(
                [str(self.location), "digest", str(path)],
                capture_output=True, text=True, check=False,
            )
        if proc.returncode != 0:
            raise RuntimeError(f"{self.name}: digest failed: {proc.stderr.strip()}")
        return proc.stdout.strip()


    def _trust(self, *args: str) -> subprocess.CompletedProcess:
        """trust-check.py for Python, the matching subcommand for Rust."""
        if self.kind == "python":
            argv = [sys.executable, str(self.location / "scripts" / "trust-check.py"), *args]
        else:
            argv = [str(self.location), *args]
        return subprocess.run(argv, capture_output=True, text=True, check=False)

    def signature(self, data: Path, sig: Path, allowed: Path, namespace: str,
                  verify_time: str) -> tuple[int, str]:
        """(exit code, status) for one signature (chapter 9)."""
        proc = self._trust("signature", str(data), "--sig", str(sig), "--allowed-signers", str(allowed),
                           "--namespace", namespace, "--verify-time", verify_time, "--json")
        try:
            return proc.returncode, json.loads(proc.stdout)["status"]
        except (json.JSONDecodeError, KeyError) as exc:
            raise RuntimeError(f"{self.name}: signature produced no status: {exc}\n{proc.stderr[:400]}")

    def advisories(self, feed: Path, sig: Path, allowed: Path, lockfile: Path,
                   verify_time: str) -> tuple[int, str, list[str]]:
        """(exit code, feed status, revoking advisory ids) for one lockfile (chapter 11)."""
        proc = self._trust("advisories", str(feed), "--sig", str(sig), "--allowed-signers", str(allowed),
                           "--lockfile", str(lockfile), "--verify-time", verify_time, "--json")
        try:
            payload = json.loads(proc.stdout)
            ids = sorted({i for hit in payload["revoked"] for i in hit["advisories"]})
            return proc.returncode, payload["advisory_feed"], ids
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RuntimeError(f"{self.name}: advisories produced no verdict: {exc}\n{proc.stderr[:400]}")

    def attest(self, kind: str, skill: Path, name: str, digest: str | None, rules: Path) -> str:
        """One canonically rendered attestation (chapter 10)."""
        args = ["attest", kind, str(skill), "--name", name]
        if digest:
            args += ["--digest", digest]
        if self.kind == "rust":
            args += ["--rules", str(rules)]
        proc = self._trust(*args)
        if proc.returncode != 0:
            raise RuntimeError(f"{self.name}: attest failed: {proc.stderr.strip()[:400]}")
        return proc.stdout


def materialise(case: dict, root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in case.get("files", {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for directory in case.get("directories", []):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for link, target in case.get("symlinks", {}).items():
        try:
            os.symlink(target, root / link)
        except OSError:
            pass  # a platform without symlinks skips the reporting assertion
    return root


def run_digest_level(impls: list[Implementation]) -> tuple[int, int, list[str]]:
    """L2. Returns (passed, total, failures)."""
    corpus = json.loads((SPEC_ROOT / "corpus" / "digest" / "cases.json").read_text(encoding="utf-8"))
    cases = corpus["cases"]
    failures: list[str] = []
    passed = 0

    with tempfile.TemporaryDirectory(prefix="agtmls-conformance-") as raw:
        tmp = Path(raw)
        for case in cases:
            root = materialise(case, tmp / case["name"])
            expected = case["expected_digest"]
            results: dict[str, str] = {}
            for impl in impls:
                try:
                    results[impl.name] = impl.digest(root)
                except RuntimeError as exc:
                    failures.append(str(exc))
                    continue

            wrong = {n: d for n, d in results.items() if d != expected}
            if wrong:
                failures.append(
                    f"{case['name']}: {case.get('why', '')}\n"
                    f"      expected {expected}\n"
                    + "".join(f"      {n:<8} {d}\n" for n, d in results.items())
                )
            else:
                passed += 1

            # Differential: even if both were wrong in the same way, say so.
            if len(set(results.values())) > 1:
                failures.append(
                    f"{case['name']}: IMPLEMENTATIONS DISAGREE\n"
                    + "".join(f"      {n:<8} {d}\n" for n, d in results.items())
                )
    return passed, len(cases), failures


def run_rules_level() -> tuple[int, int, list[str]]:
    """Every rule must satisfy its own declared examples."""
    import re

    failures: list[str] = []
    rules = sorted((SPEC_ROOT / "rules").glob("*.toml"))
    checked = 0

    def literal(text: str, key: str) -> str | None:
        match = re.search(rf"^{key} = '''(.*?)'''", text, re.MULTILINE | re.DOTALL)
        return match.group(1) if match else None

    def collect(text: str, table: str) -> list[str]:
        return re.findall(rf"\[\[{table}\]\]\ntext = '''(.*?)'''", text, re.DOTALL)

    for path in rules:
        text = path.read_text(encoding="utf-8")
        rule_id = literal(text, "id") or re.search(r'^id = "(.*?)"', text, re.MULTILINE).group(1)
        if rule_id != path.stem:
            failures.append(f"{path.name}: declares id {rule_id!r}")
        pattern = literal(text, "pattern")
        if pattern is None:
            continue
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            failures.append(f"{rule_id}: pattern does not compile: {exc}")
            continue

        def flatten(value: str) -> str:
            return re.sub(r"\s+", " ", value)

        for example in collect(text, "true_positive"):
            checked += 1
            if not compiled.search(flatten(example)):
                failures.append(f"{rule_id}: true_positive not matched: {example!r}")
        for example in collect(text, "false_positive"):
            checked += 1
            if compiled.search(flatten(example)):
                failures.append(f"{rule_id}: false_positive IS matched: {example!r}")

    return checked, checked + len(failures), failures


def run_analyzer_level(impls: list[Implementation]) -> tuple[int, int, list[str]]:
    """L3. Every implementation must report the same rules for the same input.

    Comparing rule ID *sets* per case, not counts: implementations legitimately
    differ on how many times they report the same rule on the same line, but
    never on whether a rule fired at all.
    """
    corpus = json.loads(
        (SPEC_ROOT / "corpus" / "security" / "corpus.json").read_text(encoding="utf-8")
    )
    cases = corpus["cases"]
    failures: list[str] = []
    passed = 0
    rules_dir = SPEC_ROOT / "rules"

    with tempfile.TemporaryDirectory(prefix="agtmls-analyzer-") as raw:
        tmp = Path(raw)
        for case in cases:
            root = materialise(case, tmp / case["name"])
            results: dict[str, set[str]] = {}
            for impl in impls:
                try:
                    results[impl.name] = impl.audit(root, rules_dir)
                except RuntimeError as exc:
                    failures.append(str(exc))

            if len(results) > 1:
                values = list(results.values())
                if any(v != values[0] for v in values):
                    detail = "".join(
                        f"      {n:<8} {sorted(r) or '(none)'}\n" for n, r in results.items()
                    )
                    only = set().union(*values) - set.intersection(*values)
                    failures.append(
                        f"{case['name']}: ANALYZERS DISAGREE on {sorted(only)}\n{detail}"
                    )
                    continue
            passed += 1
    return passed, len(cases), failures


def build_install_fixture(python: Implementation, root: Path) -> Path | None:
    """Create an installed tree, then tamper with it.

    Built rather than committed: a fixture recorded on disk goes stale the
    moment a skill changes, and would then be testing yesterday's digests. A
    tampered tree is the case that matters, because agreeing that a clean tree
    is clean is the easy half.
    """
    target = root / "install"
    target.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(target)], check=False, capture_output=True)
    proc = subprocess.run(
        [sys.executable, str(python.location / "scripts" / "agtmls.py"),
         "install", "rust", "claude", "--target", str(target), "--copy"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0 or not (target / ".agtmls" / "manifest.json").exists():
        return None

    skills = sorted((target / ".claude" / "skills").iterdir())
    if len(skills) >= 2:
        # One modified, one removed: both implementations must report both.
        (skills[0] / "SKILL.md").write_text("tampered\n", encoding="utf-8")
        shutil.rmtree(skills[1])
    return target


def run_registry_level(impls: list[Implementation], fixture: Path) -> tuple[int, int, list[str]]:
    """L4. Implementations must agree about whether an install can be trusted.

    A lockfile is an interop format: one implementation writes it, another may
    verify it. Disagreeing about a tampered tree is the failure that matters,
    because it means one of them would pass an install the other rejects.
    """
    failures: list[str] = []
    results: dict[str, tuple[int, set[tuple[str, str]]]] = {}
    for impl in impls:
        try:
            results[impl.name] = impl.verify_install(fixture, "claude")
        except RuntimeError as exc:
            failures.append(str(exc))

    if len(results) > 1:
        codes = {name: code for name, (code, _) in results.items()}
        if len(set(codes.values())) > 1:
            failures.append(f"exit codes disagree: {codes}")
        problems = {name: problems for name, (_, problems) in results.items()}
        values = list(problems.values())
        if any(v != values[0] for v in values):
            detail = "".join(f"      {n:<8} {sorted(v)}\n" for n, v in problems.items())
            failures.append(f"verify results disagree\n{detail}")
    return (0 if failures else 1), 1, failures


def _agree(label: str, results: dict[str, object], expected: object) -> list[str]:
    """Failures for results that miss `expected` or disagree with each other."""
    failures = []
    wrong = {name: got for name, got in results.items() if got != expected}
    if wrong:
        failures.append(f"{label}: expected {expected!r}\n"
                        + "".join(f"      {n:<8} {g!r}\n" for n, g in results.items()))
    elif len({repr(v) for v in results.values()}) > 1:
        failures.append(f"{label}: IMPLEMENTATIONS DISAGREE\n"
                        + "".join(f"      {n:<8} {g!r}\n" for n, g in results.items()))
    return failures


SIGNATURE_EXIT = {"verified": 0, "bad_signature": 5, "unsigned": 4}
ADVISORY_EXIT = {"clean": 0, "revoked": 6, "bad_signature": 5, "unsigned": 4}


def run_trust_level(impls: list[Implementation]) -> tuple[int, int, list[str]]:
    """L5. Chapters 9, 10 and 11, against their vectors and each other.

    Signatures and advisories are judged at each vector's fixed verification
    time, on exit code and status together; attestations are compared byte
    for byte, since their rendering is canonical.
    """
    failures: list[str] = []
    passed = total = 0
    corpus = SPEC_ROOT / "corpus"

    sig_dir = corpus / "signatures"
    sigs = json.loads((sig_dir / "cases.json").read_text(encoding="utf-8"))
    for case in sigs["cases"]:
        total += 1
        sig = sig_dir / (case["signature"] or "absent.sig")
        results: dict[str, object] = {}
        for impl in impls:
            try:
                results[impl.name] = impl.signature(
                    sig_dir / case["index"], sig, sig_dir / sigs["allowed_signers"],
                    sigs["namespace"], case["verify_time"])
            except RuntimeError as exc:
                failures.append(str(exc))
        found = _agree(f"signatures/{case['name']}", results,
                       (SIGNATURE_EXIT[case["expected"]], case["expected"]))
        failures += found
        passed += not found and len(results) == len(impls)

    adv_dir = corpus / "advisories"
    advs = json.loads((adv_dir / "cases.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="agtmls-l5-") as raw:
        for case in advs["cases"]:
            total += 1
            lock = Path(raw) / f"{case['name']}.json"
            lock.write_text(json.dumps(case["lockfile"]), encoding="utf-8")
            sig = adv_dir / (case["signature"] or "absent.sig")
            results = {}
            for impl in impls:
                try:
                    code, status, ids = impl.advisories(
                        adv_dir / advs["feed"], sig, adv_dir / advs["allowed_signers"], lock,
                        advs["verify_time"])
                    verdict = ("revoked" if ids else "clean") if status == "verified" else status
                    results[impl.name] = (code, verdict, ids)
                except RuntimeError as exc:
                    failures.append(str(exc))
            expected = (ADVISORY_EXIT[case["expected"]], case["expected"], case["advisories"])
            found = _agree(f"advisories/{case['name']}", results, expected)
            failures += found
            passed += not found and len(results) == len(impls)

    att_dir = corpus / "attestations"
    inputs = json.loads((att_dir / "inputs.json").read_text(encoding="utf-8"))
    digest_cases = {c["name"]: c for c in json.loads(
        (corpus / "digest" / "cases.json").read_text(encoding="utf-8"))["cases"]}
    runs = [("manifest", m["vector"], digest_cases[m["digest_case"]], m["skill"], None)
            for m in inputs["manifests"]]
    runs += [("capabilities", c["vector"], c, c["skill"], c["digest"]) for c in inputs["capabilities"]]
    with tempfile.TemporaryDirectory(prefix="agtmls-l5-attest-") as raw:
        for kind, vector, case, name, digest in runs:
            total += 1
            skill = materialise(case, Path(raw) / vector)
            results = {}
            for impl in impls:
                try:
                    results[impl.name] = impl.attest(kind, skill, name, digest, SPEC_ROOT / "rules")
                except RuntimeError as exc:
                    failures.append(str(exc))
            want = (att_dir / vector).read_text(encoding="utf-8")
            found = _agree(f"attestations/{vector}", results, want)
            failures += found
            passed += not found and len(results) == len(impls)
    return passed, total, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("--python", type=Path, help="path to an agtmls checkout")
    parser.add_argument("--rust", type=Path, help="path to an agtmls-rs binary")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--install-fixture", type=Path,
        help="an installed tree with a lockfile, for the L4 differential",
    )
    args = parser.parse_args()

    impls: list[Implementation] = []
    if args.python:
        impls.append(Implementation("python", "python", args.python.resolve()))
    if args.rust:
        impls.append(Implementation("rust", "rust", args.rust.resolve()))
    if not impls:
        parser.print_help(sys.stderr)
        return 2

    report: dict[str, object] = {"implementations": [i.name for i in impls], "levels": {}}
    failed = False

    rules_passed, rules_total, rules_failures = run_rules_level()
    report["levels"]["rules"] = {
        "checked": rules_passed, "failures": rules_failures,
    }
    failed |= bool(rules_failures)

    digest_passed, digest_total, digest_failures = run_digest_level(impls)
    report["levels"]["L2-verifier"] = {
        "passed": digest_passed, "total": digest_total, "failures": digest_failures,
    }
    failed |= bool(digest_failures)

    analyzer_passed, analyzer_total, analyzer_failures = (0, 0, [])
    if len(impls) > 1:
        analyzer_passed, analyzer_total, analyzer_failures = run_analyzer_level(impls)
        report["levels"]["L3-analyzer"] = {
            "passed": analyzer_passed, "total": analyzer_total, "failures": analyzer_failures,
        }
        failed |= bool(analyzer_failures)

    registry_passed, registry_total, registry_failures = (0, 0, [])
    python_impl = next((i for i in impls if i.kind == "python"), None)
    if len(impls) > 1 and (args.install_fixture or python_impl):
        with tempfile.TemporaryDirectory(prefix="agtmls-l4-") as raw:
            fixture = args.install_fixture.resolve() if args.install_fixture else None
            if fixture is None and python_impl is not None:
                fixture = build_install_fixture(python_impl, Path(raw))
            if fixture is None:
                registry_failures = ["could not build an install fixture"]
            else:
                registry_passed, registry_total, registry_failures = run_registry_level(
                    impls, fixture
                )
        report["levels"]["L4-registry"] = {
            "passed": registry_passed, "total": registry_total, "failures": registry_failures,
        }
        failed |= bool(registry_failures)

    trust_passed, trust_total, trust_failures = run_trust_level(impls)
    report["levels"]["L5-trust"] = {
        "passed": trust_passed, "total": trust_total, "failures": trust_failures,
    }
    failed |= bool(trust_failures)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        names = ", ".join(i.name for i in impls)
        print(f"Implementations under test: {names}")
        print()
        print(f"  rules self-test   {rules_passed} example(s) checked"
              f"{'' if not rules_failures else f' -- {len(rules_failures)} FAILED'}")
        for failure in rules_failures:
            print(f"    FAIL {failure}")
        print(f"  L2 verifier       {digest_passed}/{digest_total} digest vector(s)")
        for failure in digest_failures:
            print(f"    FAIL {failure}")
        if registry_total:
            print(f"  L4 registry       {registry_passed}/{registry_total} lockfile verification agrees")
            for failure in registry_failures:
                print(f"    FAIL {failure}")
        if analyzer_total:
            print(f"  L3 analyzer       {analyzer_passed}/{analyzer_total} security case(s) agree")
            for failure in analyzer_failures:
                print(f"    FAIL {failure}")
        print(f"  L5 trust          {trust_passed}/{trust_total} signature, advisory and attestation vector(s)")
        for failure in trust_failures:
            print(f"    FAIL {failure}")
        print()
        if failed:
            print("FAIL: conformance failed")
        elif len(impls) > 1:
            print(f"OK: {len(impls)} implementations conform and agree with each other")
        else:
            print(f"OK: {impls[0].name} conforms")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

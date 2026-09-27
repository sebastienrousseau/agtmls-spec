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
import re
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


def _ask(impls: list[Implementation], call) -> tuple[dict[str, object], list[str]]:
    """Each implementation's answer to `call(impl)`, and the errors of those
    that could not answer."""
    results: dict[str, object] = {}
    failures: list[str] = []
    for impl in impls:
        try:
            results[impl.name] = call(impl)
        except RuntimeError as exc:
            failures.append(str(exc))
    return results, failures


def _digest_case(case: dict, impls: list[Implementation], tmp: Path) -> tuple[bool, list[str]]:
    """(passed, failures) for one digest vector."""
    root = materialise(case, tmp / case["name"])
    expected = case["expected_digest"]
    results, failures = _ask(impls, lambda impl: impl.digest(root))
    rows = "".join(f"      {n:<8} {d}\n" for n, d in results.items())
    wrong = {n: d for n, d in results.items() if d != expected}
    if wrong:
        failures.append(f"{case['name']}: {case.get('why', '')}\n      expected {expected}\n" + rows)
    # Differential: even if both were wrong in the same way, say so.
    if len(set(results.values())) > 1:
        failures.append(f"{case['name']}: IMPLEMENTATIONS DISAGREE\n" + rows)
    return not wrong, failures


def run_digest_level(impls: list[Implementation]) -> tuple[int, int, list[str]]:
    """L2. Returns (passed, total, failures)."""
    corpus = json.loads((SPEC_ROOT / "corpus" / "digest" / "cases.json").read_text(encoding="utf-8"))
    cases = corpus["cases"]
    failures: list[str] = []
    passed = 0
    with tempfile.TemporaryDirectory(prefix="agtmls-conformance-") as raw:
        for case in cases:
            ok, found = _digest_case(case, impls, Path(raw))
            passed += ok
            failures += found
    return passed, len(cases), failures


def _literal(text: str, key: str) -> str | None:
    match = re.search(rf"^{key} = '''(.*?)'''", text, re.MULTILINE | re.DOTALL)
    return match.group(1) if match else None


def _collect(text: str, table: str) -> list[str]:
    return re.findall(rf"\[\[{table}\]\]\ntext = '''(.*?)'''", text, re.DOTALL)


def _flatten(value: str) -> str:
    return re.sub(r"\s+", " ", value)


def _check_rule(path: Path) -> tuple[int, list[str]]:
    """(examples checked, failures) for one rule file."""
    text = path.read_text(encoding="utf-8")
    rule_id = _literal(text, "id") or re.search(r'^id = "(.*?)"', text, re.MULTILINE).group(1)
    failures = [f"{path.name}: declares id {rule_id!r}"] if rule_id != path.stem else []
    pattern = _literal(text, "pattern")
    if pattern is None:
        return 0, failures
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return 0, [*failures, f"{rule_id}: pattern does not compile: {exc}"]
    positives = _collect(text, "true_positive")
    negatives = _collect(text, "false_positive")
    failures += [f"{rule_id}: true_positive not matched: {e!r}" for e in positives if not compiled.search(_flatten(e))]
    failures += [f"{rule_id}: false_positive IS matched: {e!r}" for e in negatives if compiled.search(_flatten(e))]
    return len(positives) + len(negatives), failures


def run_rules_level() -> tuple[int, int, list[str]]:
    """Every rule must satisfy its own declared examples."""
    failures: list[str] = []
    checked = 0
    for path in sorted((SPEC_ROOT / "rules").glob("*.toml")):
        count, found = _check_rule(path)
        checked += count
        failures += found
    return checked, checked + len(failures), failures


def _analyzer_case(case: dict, impls: list[Implementation], tmp: Path, rules_dir: Path) -> tuple[bool, list[str]]:
    """(agreed, failures) for one security case."""
    root = materialise(case, tmp / case["name"])
    results, failures = _ask(impls, lambda impl: impl.audit(root, rules_dir))
    values = list(results.values())
    if len(results) > 1 and any(v != values[0] for v in values):
        detail = "".join(f"      {n:<8} {sorted(r) or '(none)'}\n" for n, r in results.items())
        only = set().union(*values) - set.intersection(*values)
        failures.append(f"{case['name']}: ANALYZERS DISAGREE on {sorted(only)}\n{detail}")
        return False, failures
    return True, failures


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
    with tempfile.TemporaryDirectory(prefix="agtmls-analyzer-") as raw:
        for case in cases:
            ok, found = _analyzer_case(case, impls, Path(raw), SPEC_ROOT / "rules")
            passed += ok
            failures += found
    return passed, len(cases), failures


# Written by build_install_fixture beside the target: the second agent's
# bundle skills, which the first agent never installed.
CODEX_ONLY = "codex-only.json"


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

    # A second agent with a bundle the first did not install (chapter 6.2,
    # "One lockfile, several agents"): its skills must never be reported
    # against the first agent's directory.
    bundle = second_agent_bundle(python)
    if bundle is not None:
        proc = subprocess.run(
            [sys.executable, str(python.location / "scripts" / "agtmls.py"),
             "install", "rust", "codex", "--target", str(target), "--copy", "--bundle", bundle],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            return None
        index = json.loads((python.location / "index.json").read_text(encoding="utf-8"))
        codex_only = sorted(s["name"] for s in index["skills"] if s.get("bundle") == bundle)
        (root / CODEX_ONLY).write_text(json.dumps(codex_only), encoding="utf-8")

    skills = sorted((target / ".claude" / "skills").iterdir())
    if len(skills) >= 2:
        # One modified, one removed: both implementations must report both.
        (skills[0] / "SKILL.md").write_text("tampered\n", encoding="utf-8")
        shutil.rmtree(skills[1])
    return target


def second_agent_bundle(python: Implementation) -> str | None:
    """A bundle in the registry the fixture is built from, or None."""
    index = python.location / "index.json"
    if not index.exists():
        return None
    bundles = sorted({s["bundle"] for s in json.loads(index.read_text(encoding="utf-8"))["skills"] if s.get("bundle")})
    return bundles[0] if bundles else None


def _verify_agreement(impls: list[Implementation], fixture: Path, agent: str) -> tuple[dict, list[str]]:
    """Each implementation's verify result for `agent`, and where they differ."""
    results, failures = _ask(impls, lambda impl: impl.verify_install(fixture, agent))
    failures = [f"{agent}: {f}" for f in failures]
    if len(results) > 1:
        codes = {name: code for name, (code, _) in results.items()}
        if len(set(codes.values())) > 1:
            failures.append(f"{agent}: exit codes disagree: {codes}")
        problems = {name: problems for name, (_, problems) in results.items()}
        values = list(problems.values())
        if any(v != values[0] for v in values):
            detail = "".join(f"      {n:<8} {sorted(v)}\n" for n, v in problems.items())
            failures.append(f"{agent}: verify results disagree\n{detail}")
    return results, failures


def _leaks(results: dict, codex_only: set[str]) -> list[str]:
    """Implementations reporting another agent's skills against claude."""
    failures = []
    for name, (_, found) in results.items():
        leaked = sorted(skill for skill, _ in found if skill in codex_only)
        if leaked:
            failures.append(f"{name}: reports codex-only skill(s) against claude: {', '.join(leaked)}")
    return failures


def run_registry_level(impls: list[Implementation], fixture: Path) -> tuple[int, int, list[str]]:
    """L4. Implementations must agree about whether an install can be trusted.

    A lockfile is an interop format: one implementation writes it, another may
    verify it. Disagreeing about a tampered tree is the failure that matters,
    because it means one of them would pass an install the other rejects.

    Agreement alone would pass two implementations that are wrong the same
    way, so the second agent is also checked absolutely: a skill of the
    bundle only that agent installed must not be reported against the first
    (6.2). Which skills those are comes from the fixture build, never from
    the lockfile under test.
    """
    failures: list[str] = []
    passed = total = 0
    agents = ["claude", "codex"] if (fixture / ".codex" / "skills").is_dir() else ["claude"]
    marker = fixture.parent / CODEX_ONLY
    codex_only = set(json.loads(marker.read_text(encoding="utf-8"))) if marker.exists() else set()
    for agent in agents:
        results, found = _verify_agreement(impls, fixture, agent)
        checks = [found]
        if agent == "claude" and codex_only:
            checks.append(_leaks(results, codex_only))
        total += len(checks)
        passed += sum(not check for check in checks)
        failures += [f for check in checks for f in check]
    return passed, total, failures


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


def _judged(label: str, results: dict, errors: list[str], expected: object, impls: list) -> tuple[int, list[str]]:
    """(1 if every implementation answered as expected, failures)."""
    found = _agree(label, results, expected)
    return int(not found and len(results) == len(impls)), errors + found


def _signature_cases(impls: list[Implementation], corpus: Path) -> tuple[int, int, list[str]]:
    sig_dir = corpus / "signatures"
    sigs = json.loads((sig_dir / "cases.json").read_text(encoding="utf-8"))
    passed, failures = 0, []
    for case in sigs["cases"]:
        sig = sig_dir / (case["signature"] or "absent.sig")
        results, errors = _ask(impls, lambda impl, case=case, sig=sig: impl.signature(
            sig_dir / case["index"], sig, sig_dir / sigs["allowed_signers"], sigs["namespace"], case["verify_time"]))
        ok, found = _judged(f"signatures/{case['name']}", results, errors,
                            (SIGNATURE_EXIT[case["expected"]], case["expected"]), impls)
        passed, failures = passed + ok, failures + found
    return passed, len(sigs["cases"]), failures


def _advisory_verdict(impl: Implementation, args: tuple) -> tuple:
    code, status, ids = impl.advisories(*args)
    return code, ("revoked" if ids else "clean") if status == "verified" else status, ids


def _advisory_cases(impls: list[Implementation], corpus: Path) -> tuple[int, int, list[str]]:
    adv_dir = corpus / "advisories"
    advs = json.loads((adv_dir / "cases.json").read_text(encoding="utf-8"))
    passed, failures = 0, []
    with tempfile.TemporaryDirectory(prefix="agtmls-l5-") as raw:
        for case in advs["cases"]:
            lock = Path(raw) / f"{case['name']}.json"
            lock.write_text(json.dumps(case["lockfile"]), encoding="utf-8")
            args = (adv_dir / advs["feed"], adv_dir / (case["signature"] or "absent.sig"),
                    adv_dir / advs["allowed_signers"], lock, advs["verify_time"])
            results, errors = _ask(impls, lambda impl, args=args: _advisory_verdict(impl, args))
            expected = (ADVISORY_EXIT[case["expected"]], case["expected"], case["advisories"])
            ok, found = _judged(f"advisories/{case['name']}", results, errors, expected, impls)
            passed, failures = passed + ok, failures + found
    return passed, len(advs["cases"]), failures


def _attestation_cases(impls: list[Implementation], corpus: Path) -> tuple[int, int, list[str]]:
    att_dir = corpus / "attestations"
    inputs = json.loads((att_dir / "inputs.json").read_text(encoding="utf-8"))
    digest_cases = {c["name"]: c for c in json.loads(
        (corpus / "digest" / "cases.json").read_text(encoding="utf-8"))["cases"]}
    runs = [("manifest", m["vector"], digest_cases[m["digest_case"]], m["skill"], None)
            for m in inputs["manifests"]]
    runs += [("capabilities", c["vector"], c, c["skill"], c["digest"]) for c in inputs["capabilities"]]
    passed, failures = 0, []
    with tempfile.TemporaryDirectory(prefix="agtmls-l5-attest-") as raw:
        for kind, vector, case, name, digest in runs:
            skill = materialise(case, Path(raw) / vector)
            results, errors = _ask(impls, lambda impl, kind=kind, skill=skill, name=name, digest=digest:
                                   impl.attest(kind, skill, name, digest, SPEC_ROOT / "rules"))
            want = (att_dir / vector).read_text(encoding="utf-8")
            ok, found = _judged(f"attestations/{vector}", results, errors, want, impls)
            passed, failures = passed + ok, failures + found
    return passed, len(runs), failures


def run_trust_level(impls: list[Implementation]) -> tuple[int, int, list[str]]:
    """L5. Chapters 9, 10 and 11, against their vectors and each other.

    Signatures and advisories are judged at each vector's fixed verification
    time, on exit code and status together; attestations are compared byte
    for byte, since their rendering is canonical.
    """
    corpus = SPEC_ROOT / "corpus"
    parts = [part(impls, corpus) for part in (_signature_cases, _advisory_cases, _attestation_cases)]
    return sum(p[0] for p in parts), sum(p[1] for p in parts), [f for p in parts for f in p[2]]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("--python", type=Path, help="path to an agtmls checkout")
    parser.add_argument("--rust", type=Path, help="path to an agtmls-rs binary")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--install-fixture", type=Path,
        help="an installed tree with a lockfile, for the L4 differential",
    )
    return parser


def _level(passed: int, total: int, failures: list[str]) -> dict[str, object]:
    return {"passed": passed, "total": total, "failures": failures}


def _registry(impls: list[Implementation], install_fixture: Path | None) -> dict[str, object] | None:
    """L4, when there is more than one implementation and a fixture to judge."""
    python_impl = next((i for i in impls if i.kind == "python"), None)
    if len(impls) < 2 or not (install_fixture or python_impl):
        return None
    with tempfile.TemporaryDirectory(prefix="agtmls-l4-") as raw:
        fixture = install_fixture.resolve() if install_fixture else build_install_fixture(python_impl, Path(raw))
        if fixture is None:
            return _level(0, 0, ["could not build an install fixture"])
        return _level(*run_registry_level(impls, fixture))


def _levels(impls: list[Implementation], install_fixture: Path | None) -> dict[str, dict[str, object]]:
    """Every level that applies, in the order the report lists them."""
    checked, _, rules_failures = run_rules_level()
    levels: dict[str, dict[str, object]] = {"rules": {"checked": checked, "failures": rules_failures}}
    levels["L2-verifier"] = _level(*run_digest_level(impls))
    if len(impls) > 1:
        levels["L3-analyzer"] = _level(*run_analyzer_level(impls))
    registry = _registry(impls, install_fixture)
    if registry is not None:
        levels["L4-registry"] = registry
    levels["L5-trust"] = _level(*run_trust_level(impls))
    return levels


# (level, label, noun, printed even when it checked nothing), in the text
# report's order.
TEXT_LINES = [
    ("L2-verifier", "L2 verifier", "digest vector(s)", True),
    ("L4-registry", "L4 registry", "lockfile verification agrees", False),
    ("L3-analyzer", "L3 analyzer", "security case(s) agree", False),
    ("L5-trust", "L5 trust", "signature, advisory and attestation vector(s)", True),
]


def _print_failures(failures: list[str]) -> None:
    for failure in failures:
        print(f"    FAIL {failure}")


def _print_text(impls: list[Implementation], levels: dict, failed: bool) -> None:
    print(f"Implementations under test: {', '.join(i.name for i in impls)}")
    print()
    rules = levels["rules"]
    suffix = f" -- {len(rules['failures'])} FAILED" if rules["failures"] else ""
    print(f"  rules self-test   {rules['checked']} example(s) checked{suffix}")
    _print_failures(rules["failures"])
    for key, label, noun, always in TEXT_LINES:
        level = levels.get(key)
        if level is None or not (always or level["total"]):
            continue
        print(f"  {label:<18}{level['passed']}/{level['total']} {noun}")
        _print_failures(level["failures"])
    print()
    if failed:
        print("FAIL: conformance failed")
    elif len(impls) > 1:
        print(f"OK: {len(impls)} implementations conform and agree with each other")
    else:
        print(f"OK: {impls[0].name} conforms")


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    kinds = [("python", args.python), ("rust", args.rust)]
    impls = [Implementation(kind, kind, path.resolve()) for kind, path in kinds if path]
    if not impls:
        parser.print_help(sys.stderr)
        return 2
    levels = _levels(impls, args.install_fixture)
    failed = any(level["failures"] for level in levels.values())
    if args.json:
        print(json.dumps({"implementations": [i.name for i in impls], "levels": levels}, indent=2))
    else:
        _print_text(impls, levels, failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

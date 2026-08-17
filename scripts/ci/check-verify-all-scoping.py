#!/usr/bin/env python3
"""Every `run` step in verify-all.sh is classified, and scoping can only ever REMOVE
steps that the diff cannot reach.

WHY THIS EXISTS. `verify-all.sh --scoped` skips steps whose declared areas the working
diff does not touch. That is a scheduling change, and a scheduling change to a gate is
one classification mistake away from being a coverage change nobody notices — the
`green-while-broken` shape. A guard bucketed WEB that actually reads `crates/**` simply
stops running on Rust-only work, and every run stays green.

So this asserts four properties, each of which has a way to go wrong:

  1. TOTALITY — every `run` step sits under an `area` declaration. An unclassified step
     would inherit whatever the previous one declared, which is the silent-drift case.
  2. VOCABULARY — every declared bucket is one the classifier can actually produce.
     `area WEBB` would match nothing and the step would never run again.
  3. THE UNBOUNDABLE ELEVEN — the guards that scan the whole tree by construction are
     declared ALWAYS. These cannot be path-filtered even in principle: they run
     `git ls-files` with no path filter, or execute every other guard.
  4. THE FOUNDER'S FALSIFICATION — a change under `scripts/` MUST still trigger the
     guard meta-gate. That is the specific claim the ruling was given on, so it is
     checked by name rather than left to follow from (1)–(3).

HONEST LIMIT, and it is the same one the meta-gate states about selftests: this proves
each step CARRIES a classification and that the classification is well-formed. It cannot
prove the classification is RIGHT — no machine reads a guard and decides which trees it
touches. That judgement was made by reading all 68 scripts' scan roots, and re-reading
them is what a reviewer owes a new `area` line.

USAGE
  check-verify-all-scoping.py            # assert the four properties
  check-verify-all-scoping.py --selftest # prove each assertion BLOCKS
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFY_ALL = ROOT / "scripts" / "verify-all.sh"

RE_RUN = re.compile(r'^\s*run\s+"([^"]*)"')
RE_AREA = re.compile(r"^\s*area\s+(.+?)\s*$")

# The buckets `_classify_changed` can emit, plus ALWAYS. Kept here rather than parsed
# out of the shell so a typo in EITHER file is caught by their disagreement.
BUCKETS = {"RUST", "WEB", "DOCS", "SCRIPTS", "CI", "INFRA", "PY", "ALWAYS"}

# Guards whose scan is UNBOUNDABLE — each runs `git ls-files` with no path filter, or
# walks the whole worktree, or (the meta-gate) executes every other guard. Together they
# cost ~11.8s of a 411.6s run, so pinning them to ALWAYS removes the entire
# "a filter un-armed a guard" class for almost nothing. Keyed by a fragment of the
# `run` label, because that is what the file actually contains.
MUST_BE_ALWAYS = [
    "ADR-051 miscite",
    "npm-scope",
    "r2-jurisdiction",
    "r2 endpoint",
    "retired logo",
    "retired-logo",
    "tenant-isolation",
    "tenants-pk-column",
    "no-e2e-auth-in-prod",
    "subprocessor",
    "never-say-again",
    "gitleaks",
    "suppression",
    # Docs guards whose FAILURE is triggered by CODE edits: both walk every anchor a doc
    # cites and `git log -L` it, so a change to crates/gateway/src/server.rs can turn
    # them red. Bucketing them DOCS would stop them catching the case they exist for.
    "doc freshness",
    "doc-freshness",
    "spec anchors",
    "spec-anchor",
    "claim anchors",
    "claim-anchor",
]

# The founder's stated falsification, checked by name.
SCRIPTS_TRIGGERED = ["guard-selftest meta-gate"]


def classified_steps(text: str) -> list[tuple[str, str | None]]:
    """(label, declared-area) for every `run` step, in file order."""
    out: list[tuple[str, str | None]] = []
    current: str | None = None
    for line in text.splitlines():
        m = RE_AREA.match(line)
        if m:
            current = m.group(1)
            continue
        m = RE_RUN.match(line)
        if m:
            out.append((m.group(1), current))
    return out


def check(text: str) -> list[str]:
    failures: list[str] = []
    steps = classified_steps(text)
    if not steps:
        # A scan that finds nothing must never pass: that is the shape where a refactor
        # renames `run` and this guard reports green over an unclassified file.
        return ["found ZERO `run` steps in verify-all.sh — the parser is broken"]

    for label, areaspec in steps:
        if areaspec is None:
            failures.append(f"{label!r}: no `area` declared before it")
            continue
        for b in areaspec.split():
            if b not in BUCKETS:
                failures.append(
                    f"{label!r}: unknown bucket {b!r} — it would match nothing "
                    f"and the step would never run under --scoped"
                )

    by_label = {label: (areaspec or "") for label, areaspec in steps}

    for frag in MUST_BE_ALWAYS:
        hits = [(k, v) for k, v in by_label.items() if frag.lower() in k.lower()]
        for k, v in hits:
            if "ALWAYS" not in v.split():
                failures.append(
                    f"{k!r} is declared {v!r} but its scan CANNOT be bounded to a "
                    f"directory — it must be ALWAYS"
                )

    for frag in SCRIPTS_TRIGGERED:
        hits = [(k, v) for k, v in by_label.items() if frag.lower() in k.lower()]
        if not hits:
            failures.append(
                f"no step matching {frag!r} — the founder's falsification "
                f"(a scripts/ change still triggers the meta-gate) cannot be checked"
            )
        for k, v in hits:
            buckets = set(v.split())
            if "SCRIPTS" not in buckets and "ALWAYS" not in buckets:
                failures.append(
                    f"{k!r} is declared {v!r}: a change under scripts/ would NOT "
                    f"trigger it. Founder ruling 2026-08-16."
                )

    return failures


def selftest() -> int:
    """Each assertion must BLOCK. A guard nobody has watched fail is decorative."""
    good = (
        "area RUST\n"
        'run "cargo test" cargo test\n'
        "area ALWAYS\n"
        'run "gitleaks (tracked snapshot)" gitleaks dir x\n'
        "area SCRIPTS\n"
        'run "guard-selftest meta-gate" python3 scripts/ci/check-guard-selftests.py\n'
    )
    cases: list[tuple[str, str, bool]] = [
        ("a well-formed file passes", good, False),
        (
            "an UNCLASSIFIED step blocks",
            'run "cargo test" cargo test\n' + good,
            True,
        ),
        (
            "an UNKNOWN bucket blocks",
            good.replace("area RUST", "area WEBB"),
            True,
        ),
        (
            "an unboundable guard bucketed away from ALWAYS blocks",
            good.replace("area ALWAYS", "area WEB"),
            True,
        ),
        (
            "the meta-gate moved off SCRIPTS blocks (the founder's falsification)",
            good.replace("area SCRIPTS", "area DOCS"),
            True,
        ),
        (
            "a file with no `run` steps blocks — an empty scan is never a pass",
            "area RUST\n# nothing here\n",
            True,
        ),
    ]
    fails = 0
    for name, text, want_block in cases:
        got = bool(check(text))
        if got == want_block:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name} — expected {'BLOCK' if want_block else 'PASS'}")
            fails += 1

    # And the real file must pass, or the guard is asserting against a fiction.
    real = check(VERIFY_ALL.read_text(encoding="utf-8"))
    if real:
        print(f"  ✗ the REAL verify-all.sh does not pass ({len(real)} finding(s)):")
        for f in real[:10]:
            print(f"      {f}")
        fails += 1
    else:
        print("  ✓ the real verify-all.sh passes")

    # THE LIVE HALF. Everything above is this file reasoning about its own table; this
    # runs the real shell classifier over a real diff in a throwaway worktree, which is
    # the only thing that can catch the two files disagreeing.
    print("  — live falsification: the REAL shell classifier, both directions —")
    fails += falsify_live()

    if fails:
        print(f"scoping-guard selftest FAILED — {fails} case(s).")
        return 1
    print("scoping-guard selftest PASSED.")
    return 0


def explain(files: list[str]) -> dict[str, str]:
    """Ask the SHELL which steps a given diff would run — never this file's model of it.

    `verify-all.sh --scoped --explain-scope` walks its own `area`/`run` structure with
    the real classifier and prints one `RUN|SKIP<TAB>label` line per step, executing
    nothing and writing no stamp. Parsing that is what makes the assertions below a
    MEASUREMENT rather than the same table restated twice — a probe that can read its
    own documentation is not a probe (docs/reference/TRAPS.md §38).
    """
    env = {**os.environ, "TRACELANE_SCOPE_FILES": "\n".join(files)}
    p = subprocess.run(
        ["bash", "scripts/verify-all.sh", "--scoped", "--explain-scope"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env=env,
    )
    out: dict[str, str] = {}
    for line in p.stdout.splitlines():
        if "\t" in line and line.split("\t", 1)[0] in ("RUN", "SKIP"):
            verdict, label = line.split("\t", 1)
            out[label] = verdict
    if not out:
        print(f"    (no verdicts; rc={p.returncode}) {p.stdout[:200]} {p.stderr[:200]}")
    return out


def falsify_live() -> int:
    """THE FOUNDER'S TEST, EXECUTED against the real classifier.

    Both directions matter. A classifier that returns "run everything" always would pass
    the scripts/ half trivially, so the docs-only half — which must SKIP — is what makes
    the first half evidence.
    """
    fails = 0

    def expect(files: list[str], label: str, want: str, match) -> int:
        res = explain(files)
        if not res:
            print(f"  x {label}: --explain-scope produced no verdicts")
            return 1
        hits = {k: v for k, v in res.items() if match(k)}
        if not hits:
            print(f"  x {label}: no step matched the selector")
            return 1
        bad = {k: v for k, v in hits.items() if v != want}
        if bad:
            for k, v in list(bad.items())[:4]:
                print(f"  x {label}: {k!r} was {v}, expected {want}")
            return len(bad)
        print(f"  + {label}: all {len(hits)} matching step(s) {want}")
        return 0

    is_meta = lambda k: "meta-gate" in k
    is_cargo = lambda k: k.startswith("cargo ")

    # 1. THE FOUNDER'S FALSIFICATION, verbatim: a change under scripts/ must still
    #    trigger the guard meta-gate.
    fails += expect(
        ["scripts/ci/some-new-guard.py"],
        "scripts/ change runs the meta-gate",
        "RUN",
        is_meta,
    )

    # 2. The other direction, or (1) is satisfied by a no-op classifier.
    fails += expect(
        ["docs/product/OBSERVE.md"],
        "docs-only change SKIPS the meta-gate",
        "SKIP",
        is_meta,
    )
    fails += expect(
        ["docs/product/OBSERVE.md"], "docs-only change SKIPS cargo", "SKIP", is_cargo
    )

    # 3. Rust work still runs cargo, and still skips the meta-gate.
    fails += expect(
        ["crates/gateway/src/server.rs"], "crates/ change runs cargo", "RUN", is_cargo
    )

    # 4. FAIL OPEN. An unclassifiable path must run EVERYTHING — the property that makes
    #    a mistake in the case arms cost time rather than coverage.
    res = explain(["some/unknown/place/thing.bin"])
    skipped = [k for k, v in res.items() if v == "SKIP"]
    if not res:
        print("  x fail-open: no verdicts")
        fails += 1
    elif skipped:
        print(f"  x fail-open: an unclassified path skipped {len(skipped)} step(s)")
        fails += 1
    else:
        print(f"  + fail-open: an unclassified path runs all {len(res)} steps")

    # 5. A markdown file ANYWHERE is a DOCS change — build-doc-index.py keys on the
    #    EXTENSION, not the directory, so a new README.md under crates/ makes the index
    #    stale. Bucketing it RUST-only would let that ship.
    fails += expect(
        ["crates/gateway/README.md"],
        "a .md under crates/ still runs the doc-index check",
        "RUN",
        lambda k: "doc-index" in k,
    )

    return fails


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        if argv[1] == "--selftest":
            return selftest()
        print(f"check-verify-all-scoping: unknown option: {argv[1]}", file=sys.stderr)
        return 2
    failures = check(VERIFY_ALL.read_text(encoding="utf-8"))
    steps = classified_steps(VERIFY_ALL.read_text(encoding="utf-8"))
    if failures:
        print(f"✗ verify-all.sh scoping: {len(failures)} finding(s)")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"OK — {len(steps)} run step(s), every one classified into a known bucket;")
    print("     the unboundable guards are ALWAYS; a scripts/ change triggers the")
    print("     meta-gate. It cannot prove a bucket is CORRECT — that is a re-read.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

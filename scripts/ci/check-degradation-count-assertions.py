#!/usr/bin/env python3
"""A test may not assert an EXACT delta on a process-global degradation counter.

WHY THIS EXISTS. `tracelane_shared::degradation` keeps ONE counter slot per kind for
the whole process. Every test in a binary shares that slot, and `cargo test` runs
tests in parallel, so a test that reads `count(kind)`, drives its path, and asserts
`count(kind) == before + 1` is racing every other test in the binary that drives the
same kind through ITS OWN path. The race is invisible on a quiet box and red on a
loaded one — which is the worst shape a test can have, because the red reads as the
gate being flaky rather than the assertion being wrong.

It happened FOUR times before this file, each fixed at the instance:

    2026-09-06  health_publishes_prompt_guard_fail_opens      692 vs 693   (block 6)
    2026-09-14  spawn_publish_with_no_runtime_counts_…        3 vs 2       (CI 34686533037)
    2026-09-16  spawn_publish_refuses_and_counts_above_…      +2 vs +1     (gate 15)
    2026-09-16  ft05_fail_open_advances_the_degradation_…     +2 vs +1     (gate 15, same run)

The fix at every one was the same and is the rule here: a test asserts that ITS
occurrence landed — `count(kind) > before` — never how many landed. "Exactly N" is a
property of a test-OWNED observable (the value `note()` returns, an in-flight figure,
the loop bound the test itself ran), not of a shared counter.

THE RULE. In any `crates/**/*.rs`, an `assert_eq!` / `assert_ne!` / `assert!(… == …)`
whose arguments read a degradation count — directly (`count(Degradation::X)`) or through
a local bound from one (`let before = count(…)`, `after = count(…)`) — is a violation
unless a written exemption sits within EXEMPT_WINDOW lines above it:

    // exact-delta-ok: <why this test is the only noter of that kind in its binary>

The shared crate's unit test of `note()` itself is the worked example: it IS the only
noter of its kinds in that binary, and it says so with the grep that proves it.

HONEST LIMIT. This reads assertion TEXT. It sees a count reaching an assertion by a
direct call or a `let`/reassignment in the same function; a count laundered through a
helper (`fn delta() -> u64`) or a struct field is invisible to it. It cannot judge
whether an exemption's single-noter argument is TRUE — only that somebody had to write
one. A `>`/`>=` assertion is accepted as the right shape without proving the test's
own occurrence is what moved the counter; that half is the test author's.

USAGE
  check-degradation-count-assertions.py             # scan crates/
  check-degradation-count-assertions.py --selftest  # plant violations, prove they block
  check-degradation-count-assertions.py --root DIR  # scan another tree (selftest uses it)
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXEMPT_MARKER = "exact-delta-ok:"
EXEMPT_WINDOW = 6  # comment lines allowed between the marker and the assert
MIN_REASON = 20  # characters; "exact-delta-ok: ok" is not a reason

# A degradation count read, in any of the spellings the tree uses.
COUNT_CALL = re.compile(
    r"(?:tracelane_shared::)?(?:degradation::)?\bcount\(\s*"
    r"(?:tracelane_shared::)?(?:degradation::)?Degradation::"
)
# `let before = count(Degradation::…)` / `let mut after = …` / `after = count(…)`.
BINDING = re.compile(
    r"(?:let\s+(?:mut\s+)?)?\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:tracelane_shared::)?(?:degradation::)?count\(\s*"
    r"(?:tracelane_shared::)?(?:degradation::)?Degradation::"
)
ASSERT_START = re.compile(r"\bassert(?:_eq|_ne)?!\s*\(")
FN_START = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+\w+", re.MULTILINE
)


def macro_args(text: str, open_paren: int) -> tuple[str, int]:
    """Text inside the balanced parens starting at `open_paren`, and the end index."""
    depth = 0
    i = open_paren
    in_str = False
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i], i
        i += 1
    return text[open_paren + 1 :], len(text)


def strip_comments(s: str) -> str:
    return re.sub(r"//[^\n]*", "", s)


def exempt_reason(lines: list[str], assert_line: int) -> str | None:
    """The reason on an `exact-delta-ok:` line within the window above, or None."""
    lo = max(0, assert_line - EXEMPT_WINDOW)
    for k in range(assert_line - 1, lo - 1, -1):
        stripped = lines[k].strip()
        if EXEMPT_MARKER in stripped:
            return stripped.split(EXEMPT_MARKER, 1)[1].strip()
        if not stripped.startswith("//"):
            break
    return None


def scan_file(path: pathlib.Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "Degradation::" not in text:
        return []
    lines = text.split("\n")
    findings: list[str] = []
    fn_starts = [m.start() for m in FN_START.finditer(text)]
    for m in ASSERT_START.finditer(text):
        args, _ = macro_args(text, m.end() - 1)
        code = strip_comments(args)
        # The function this assert lives in: from the nearest `fn` above.
        fn_from = max((s for s in fn_starts if s < m.start()), default=0)
        body_before = strip_comments(text[fn_from : m.start()])
        bound = {b.group(1) for b in BINDING.finditer(body_before)}
        direct = bool(COUNT_CALL.search(code))
        via_local = any(re.search(rf"\b{re.escape(v)}\b", code) for v in bound)
        if not (direct or via_local):
            continue
        macro = m.group(0).rstrip("(").strip()
        # `assert!` is only a delta claim when it compares for equality.
        if macro == "assert!" and not re.search(r"(?<![<>!=])==(?!=)", code):
            continue
        line_no = text.count("\n", 0, m.start())  # 0-based
        reason = exempt_reason(lines, line_no)
        if reason is not None and len(reason) >= MIN_REASON:
            continue
        how = (
            "no exemption"
            if reason is None
            else f"exemption reason too short ({reason!r})"
        )
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        findings.append(
            f"{rel}:{line_no + 1}: {macro} asserts an exact delta on a process-global "
            f"degradation counter ({how}) — assert `> before`, or write "
            f"`// {EXEMPT_MARKER} <why this is the only noter in its binary>`"
        )
    return findings


def scan(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(root.rglob("*.rs")):
        if "/target/" in path.as_posix():
            continue
        findings.extend(scan_file(path))
    return findings


def selftest() -> int:
    cases: list[tuple[str, str, bool]] = [
        (
            "exact_direct",
            (
                "fn t() {\n    let before = count(Degradation::X);\n"
                "    assert_eq!(count(Degradation::X), before + 1);\n}\n"
            ),
            True,
        ),
        (
            "exact_via_after_minus_before",
            (
                "fn t() {\n    let before = tracelane_shared::degradation::count(\n"
                "        tracelane_shared::degradation::Degradation::X,\n    );\n"
                "    let after = tracelane_shared::degradation::count(\n"
                "        tracelane_shared::degradation::Degradation::X,\n    );\n"
                '    assert_eq!(after - before, 2, "two");\n}\n'
            ),
            True,
        ),
        (
            "exact_via_plain_assert_eq_operator",
            (
                "fn t() {\n    let before = count(Degradation::X);\n"
                "    assert!(count(Degradation::X) == before + 1);\n}\n"
            ),
            True,
        ),
        (
            "monotonic_is_the_right_shape",
            (
                "fn t() {\n    let before = count(Degradation::X);\n"
                '    assert!(count(Degradation::X) > before, "landed");\n}\n'
            ),
            False,
        ),
        (
            "monotonic_ge_with_local",
            (
                "fn t() {\n    let before = count(Degradation::X);\n"
                "    let after = count(Degradation::X);\n"
                "    assert!(after - before >= 1);\n}\n"
            ),
            False,
        ),
        (
            "exempt_with_reason",
            (
                "fn t() {\n    let before = count(Degradation::X);\n"
                "    // exact-delta-ok: the unit test of note() and the only noter of X here\n"
                "    assert_eq!(count(Degradation::X), before + 1);\n}\n"
            ),
            False,
        ),
        (
            "exempt_reason_too_short",
            (
                "fn t() {\n    let before = count(Degradation::X);\n"
                "    // exact-delta-ok: ok\n"
                "    assert_eq!(count(Degradation::X), before + 1);\n}\n"
            ),
            True,
        ),
        (
            "exempt_marker_out_of_window",
            (
                "fn t() {\n    // exact-delta-ok: a reason that is far above the assertion\n"
                "    let before = count(Degradation::X);\n"
                "    let x = 1;\n"
                "    assert_eq!(count(Degradation::X), before + 1);\n}\n"
            ),
            True,
        ),
        (
            "unrelated_before_is_not_a_count",
            (
                "fn t() {\n    let before = in_flight();\n"
                "    let _c = count(Degradation::X);\n"
                "    assert_eq!(in_flight(), before);\n}\n"
            ),
            False,
        ),
        (
            "binding_in_another_fn_does_not_leak",
            (
                "fn a() {\n    let before = count(Degradation::X);\n    let _ = before;\n}\n"
                "fn b() {\n    let before = 3;\n    assert_eq!(4, before + 1);\n}\n"
            ),
            False,
        ),
    ]
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        for name, src, expect_block in cases:
            f = root / f"{name}.rs"
            f.write_text(src)
            got = scan_file(f)
            blocked = bool(got)
            mark = "✓" if blocked == expect_block else "✗"
            if blocked != expect_block:
                bad += 1
            print(
                f"  {mark} {name}: {'BLOCKED' if blocked else 'passed'} "
                f"(expected {'BLOCK' if expect_block else 'pass'})"
            )
            for g in got:
                print(f"      {g}")
    if bad:
        print(f"✗ selftest: {bad} case(s) did not behave as expected")
        return 1
    print(
        f"✓ selftest: {len(cases)} cases — exact deltas block, `>` passes, "
        f"exemptions need a reason within {EXEMPT_WINDOW} lines"
    )
    return 0


def main(argv: list[str]) -> int:
    root = ROOT / "crates"
    args = list(argv)
    if "--selftest" in args:
        if len(args) != 1:
            print("✗ --selftest takes no other arguments")
            return 2
        return selftest()
    if "--root" in args:
        i = args.index("--root")
        if i + 1 >= len(args):
            print("✗ --root needs a directory")
            return 2
        root = pathlib.Path(args[i + 1])
        del args[i : i + 2]
    if args:
        print(f"✗ unknown argument(s): {' '.join(args)}")
        print((__doc__ or "").split("USAGE", 1)[1])
        return 2
    findings = scan(root)
    if findings:
        print("✗ exact-delta assertions on process-global degradation counters:")
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"✓ degradation-count assertions: no exact delta on a shared counter under {root}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

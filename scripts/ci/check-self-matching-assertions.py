#!/usr/bin/env python3
"""A guard that greps the file containing it must not be satisfiable BY ITS OWN LINE.

WHY. This is the repo's most-repeated defect class — `docs/reference/TRAPS.md` §19
("a control that matches a WORD instead of a CONSTRUCTION") and §38 ("a probe that can
read its own documentation is not a probe"). It has 40+ recorded instances. Its most
expensive shape is a guard inside a script asserting something about that same script:

    if grep -q 'final_repeat=1' "$0"; then echo "the notice exists"; fi

The pattern `final_repeat=1` appears ON THE GREP'S OWN LINE, so the assertion is true
whether or not the feature exists. Three guards of exactly this shape were written on
2026-09-01 and all three passed against builds with their features deliberately removed,
inside a 56-case selftest that was otherwise green.

THE ONLY EXISTING CONTROL FOR THE CLASS DOES NOT COVER THIS.
`scripts/hooks/protect-self-matching-process-probe.sh` inspects Bash TOOL CALLS for
`pgrep -f` / `ps | grep`. It never opens a repo file. It has been armed since 2026-08-16
and seven instances of this shape landed in `scripts/ops/tlane-watchdog.sh` after it.
CLAUDE.md §12: a lesson still in prose after it has earned a gate is context debt.

THE TEST IS EXACT, NOT HEURISTIC — which is what keeps it from crying wolf (§38's own
warning: a guard that fires on prose gets switched off). For each `grep <pattern> "$0"`
we run the pattern AGAINST THE LINE ITSELF. If it matches, the assertion is satisfiable
by its own source and is reported. If it cannot match, the line is anchored safely and
passes. So this is legal and untouched:

    grep -qE '^[[:space:]]*sig="[^"]*capture_dead' "$0"   # cannot match `  if grep -qE ...`

THE FIX, when it fires: slice your own source out first and match the slice.

    body=$(sed -n '/^MAIN_BODY_ANCHOR/,$p' "$0")
    grep -q 'final_repeat=1' <<< "$body"

HONEST LIMIT, stated because the class is about controls that overstate themselves:
this sees a grep whose TARGET is literally `$0`/`$BASH_SOURCE`. A self-match reached
through a variable holding the whole file, or through a `sed`-slice whose range still
covers the assertion, is invisible to it. That half is review. It also does not check
the OTHER half of the rule — that a falsification must be proven to have MUTATED before
its result means anything — which has a reference implementation in
`scripts/ci/run-postgres-integration.sh` and `run-clickhouse-integration.sh` and no
generic gate, because a generic detector for it would be low-precision.

USAGE
  check-self-matching-assertions.py            # scan the tree
  check-self-matching-assertions.py --selftest # prove it BLOCKS on a planted violation
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# A grep/rg whose target is the running script itself.
SELF_TARGET = re.compile(
    r'"\$0"|\s\$0(?=[\s;)]|$)|"\$\{BASH_SOURCE\[0\]\}"|\$BASH_SOURCE'
)
GREP_CALL = re.compile(r"\b(?:grep|rg)\b((?:\s+-[A-Za-z-]+)*)\s+('[^']*'|\"[^\"]*\")")


def _to_python_re(pat: str, extended: bool) -> str | None:
    """Best-effort ERE/BRE -> Python. Returns None when we cannot be confident.

    Confidence matters more than coverage here: a pattern we mis-translate could
    produce a FALSE finding, and a guard that cries wolf is the thing §38 warns
    about. An untranslatable pattern is reported as UNPARSED, never as clean.
    """
    p = pat.replace("[[:space:]]", r"\s").replace("[[:alnum:]]", r"[A-Za-z0-9]")
    p = p.replace("[[:digit:]]", r"\d").replace("[[:alpha:]]", "[A-Za-z]")
    if "[[:" in p:
        return None
    if not extended:
        # BRE: `\(` `\)` `\{` `\}` are the METACHARACTERS and bare `( ) { }` are
        # LITERAL — the opposite of ERE. This function used to BAIL on a bare paren,
        # which made it return UNPARSED for `(( prev_repeats < REALERT_MAX_REPEATS ))`
        # — i.e. it could not see the exact 2026-09-01 defect it was written for.
        # Caught by falsifying against that real line rather than a synthetic one.
        # Swap the two roles instead of giving up: sentinel the escaped forms, escape
        # what is left, then restore.
        p = (
            p.replace(r"\(", "\x00")
            .replace(r"\)", "\x01")
            .replace(r"\{", "\x02")
            .replace(r"\}", "\x03")
        )
        p = re.sub(r"[(){}]", lambda m: "\\" + m.group(0), p)
        p = (
            p.replace("\x00", "(")
            .replace("\x01", ")")
            .replace("\x02", "{")
            .replace("\x03", "}")
        )
    try:
        re.compile(p)
    except re.error:
        return None
    return p


def _rel(path: Path) -> str:
    """Relative to ROOT when inside it, absolute otherwise — the selftest scans a
    temp dir, and a crash there would make the guard unable to prove it blocks."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def scan_file(path: Path) -> tuple[list[str], list[str]]:
    findings: list[str] = []
    unparsed: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings, unparsed
    for n, line in enumerate(lines, 1):
        m = GREP_CALL.search(line)
        if not m:
            continue
        # THE SELF-TARGET MUST BE THE GREP'S OWN FILE ARGUMENT — so it has to appear
        # AFTER the pattern, and with no pipe between. `bash "$0" --tick | grep -q 'X'`
        # greps the script's OUTPUT, not its source, and is perfectly sound; flagging it
        # would make this guard cry wolf on four correct lines in sprint-autopilot.sh,
        # which is precisely how §38 says a guard gets switched off. Caught by running
        # this against the real tree before wiring it up, not by reasoning about it.
        rest = line[m.end() :]
        if "|" in rest.split("#", 1)[0]:
            continue
        if not SELF_TARGET.search(rest):
            continue
        flags, quoted = m.group(1) or "", m.group(2)
        pat = quoted[1:-1]
        if not pat:
            continue
        extended = "E" in flags.replace("--", "")
        py = _to_python_re(pat, extended)
        if py is None:
            unparsed.append(f"{_rel(path)}:{n}: UNPARSED pattern {quoted}")
            continue
        if "F" in flags.replace("--", ""):
            hit = pat in line
        else:
            try:
                hit = re.search(py, line) is not None
            except re.error:
                unparsed.append(f"{_rel(path)}:{n}: UNPARSED {quoted}")
                continue
        if hit:
            findings.append(
                f"{_rel(path)}:{n}: pattern {quoted} MATCHES ITS OWN LINE\n"
                f"    {line.strip()[:120]}\n"
                f"    -> slice your own source out first, then match the slice."
            )
    return findings, unparsed


def tracked_shell_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.sh", "*.bash"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return [ROOT / p for p in out.stdout.split("\0") if p]


def main() -> int:
    files = tracked_shell_files()
    if not files:
        print("✗ CANNOT DETERMINE — `git ls-files` returned no shell files.")
        return 1
    findings: list[str] = []
    unparsed: list[str] = []
    for f in files:
        a, b = scan_file(f)
        findings += a
        unparsed += b
    for u in unparsed:
        print(f"  {u}")
    if unparsed:
        print(
            f"\n✗ {len(unparsed)} pattern(s) over a script's own source could NOT be\n"
            f"  parsed, so this guard cannot say whether they self-match. A control that\n"
            f"  cannot run is not a control that passes (CLAUDE.md §14). Anchor the\n"
            f"  pattern, or slice the source and match the slice."
        )
        return 1
    if findings:
        print(
            f"✗ {len(findings)} self-matching assertion(s) — each passes by construction:\n"
        )
        for f in findings:
            print(f"  {f}\n")
        return 1
    print(
        f"OK — {len(files)} shell file(s); every grep over a script's own source was\n"
        f"  parsed and none is satisfiable by its own line."
    )
    return 0


def selftest() -> int:
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        bad = Path(td) / "bad.sh"
        bad.write_text(
            "#!/bin/bash\nif grep -q 'final_repeat=1' \"$0\"; then echo ok; fi\n"
        )
        f, _ = scan_file(bad)
        if f:
            print("  ✓ a pattern that matches its own line is CAUGHT")
        else:
            print("  ✗ the planted self-match was NOT caught")
            fails += 1

        good = Path(td) / "good.sh"
        good.write_text(
            "#!/bin/bash\nif grep -qE '^sig=.*capture_dead' \"$0\"; then echo ok; fi\n"
        )
        f, _ = scan_file(good)
        if not f:
            print(
                "  ✓ an ANCHORED pattern that cannot match its own line PASSES (no wolf-crying)"
            )
        else:
            print(f"  ✗ false positive on a safely-anchored pattern: {f}")
            fails += 1

        sliced = Path(td) / "sliced.sh"
        sliced.write_text(
            "#!/bin/bash\nbody=$(sed -n '/^X/,$p' \"$0\")\ngrep -q 'final_repeat=1' <<< \"$body\"\n"
        )
        f, _ = scan_file(sliced)
        if not f:
            print(
                "  ✓ the SLICE-THEN-MATCH fix is not flagged (the guard names a real fix)"
            )
        else:
            print(f"  ✗ flagged the correct fix: {f}")
            fails += 1

        unp = Path(td) / "unp.sh"
        unp.write_text("#!/bin/bash\ngrep -q '[[:xdigit:]]zz' \"$0\"\n")
        _, u = scan_file(unp)
        if u:
            print("  ✓ an unparseable pattern is REPORTED, never assumed clean (§14)")
        else:
            print("  ✗ an unparseable pattern was silently treated as clean")
            fails += 1

    if fails == 0:
        print("selftest PASSED.")
        return 0
    print(f"selftest FAILED — {fails} case(s).")
    return 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--selftest":
            sys.exit(selftest())
        print(f"unknown argument: {sys.argv[1]}", file=sys.stderr)
        sys.exit(2)
    sys.exit(main())

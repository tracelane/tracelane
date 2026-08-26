#!/usr/bin/env python3
"""A proof's PRINTED verdict and its EXIT verdict are two separate claims.

WHY THIS EXISTS — founder ruling R105, 2026-08-23.

`scripts/deploy/gateway.sh` decides whether production keeps a new binary by reading each
proof's **exit status**. Every proof also **prints** a verdict a human reads. Nothing makes
the two agree, and within one week this repo produced BOTH failure directions:

  * **`overhead-proof.sh` (Proof E) printed a PASS and exited 1.** The last statement was
    `[ … ] && [ … ] && echo`, which returns non-zero on the normal branch, so the script's
    status was that chain's. `gateway.sh` reads a non-zero Proof E as a regression and
    **ROLLS BACK** — a healthy deploy reverted on the strength of a green line. Found by
    running it twice rather than once; the first run took the other branch.

  * **`audit-live-proof.sh` (Proof C) prints a FAILURE and exits 0.** Its `else` branch
    prints `RESULT: ✗ unexpected — GREEN should be exit 0, RED exit 1` and then falls
    through to an `echo`, which succeeds. So `gateway.sh`'s
    `|| { rollback; die "audit-live-proof FAILED"; }` **never fires**, and a deploy whose
    audit chain did not verify prints `✅ DEPLOY GREEN`. That is a false green on the
    tamper-evident ledger — the product's core claim — and it is the worse direction of
    the two by a wide margin.

Its sibling `anchor-live-proof.sh` has the identical summary block WITH an `exit 1` in the
else. Two scripts, same shape, one correct — which is exactly how it stayed invisible: a
reader who checked one would have concluded the other was fine.

**THIS IS THE EXACT INVERSE OF THE WRAPPER-EXIT-CODE TRAP** (`CLAUDE.md` §14, and the
`protect-piped-exit-code` hook): there, a real failure hid behind a wrapper's success. Here,
a printed verdict and the process status disagree in whichever direction the last statement
happens to return.

WHAT IT CHECKS, and both properties are decidable from the text:

  P1  Every branch that PRINTS a failure marker must `exit` non-zero (or `die`, or `return`
      non-zero) before that branch closes. A printed `✗` that falls through is a lie the
      caller cannot see.
  P2  The script's LAST statement must have a deterministic status — an explicit `exit`, or
      a `case`/`if` whose every terminal branch exits. A trailing `echo`, comment or `&&`
      chain makes the exit status an accident of the last line.

HONEST LIMITS, because a guard that hides its blind spot is worse than none:
  * It is a line scanner, not a bash parser. A failure printed from a helper FUNCTION the
    branch calls is invisible to it, as is one built by string interpolation.
  * It cannot tell a "failure marker" from a word. The vocabulary is explicit and listed
    below; a proof that reports failure in other words is not covered.
  * It says nothing about whether the proof MEASURES the right thing. It only makes the two
    verdicts agree.

USAGE
  check-proof-exit-verdicts.py            check every deploy-path proof
  check-proof-exit-verdicts.py --selftest plant both real bugs and prove it refuses
EXIT 0 clean · 1 a proof's printed and exit verdicts can disagree · 2 cannot determine
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# THE DEPLOY PATH, named explicitly rather than globbed. A glob would silently start
# covering a new file and silently stop covering a renamed one; this list is the claim.
PROOFS = [
    "scripts/proofs/audit-live-proof.sh",
    "scripts/proofs/anchor-live-proof.sh",
    "scripts/proofs/overhead-proof.sh",
    "scripts/ci/check-trace-summary-consistency.sh",
    "scripts/ops/check-deploy-provenance.sh",
]

# Explicit vocabulary. Anything a human would read as "this proof did not pass".
FAILURE_MARK = re.compile(
    r"(✗|❌|🔴|\bFAIL\b|\bFAILED\b|REGRESS|INCONSIST|unexpected —|CANNOT BE DETERMINED"
    r"|CANNOT DETERMINE|did NOT|does not verify)"
)
# A line that PRINTS. Assignments and comparisons that merely mention a word do not count.
PRINTS = re.compile(r"^\s*(echo|printf|say)\b")
# Satisfying a printed failure. THREE FORMS, and the first two were missing from the first
# version of this guard — which then reported four false positives and one real bug, and a
# guard whose list is mostly noise is one nobody reads:
#
#   1. `exit N` / `die` / `return N` on a LATER line in the same branch.
#   2. THE SAME LINE, after a `;`. `echo "❌ …"; exit 2` is the most compact correct form
#      there is, and flagging it would train people to spread it over two lines for the
#      guard's benefit.
#   3. AN ACCUMULATOR — `fails=1`, `ok=false`, `rc=1`. A selftest that collects every
#      failing case and exits once at the end is CORRECT and is the dominant shape in this
#      repo's guards. Treating it as a violation would flag every one of them.
SATISFIES = re.compile(
    r"(^\s*(exit\s+[1-9]|die\b|return\s+[1-9])"
    r"|;\s*(exit\s+[1-9]|die\b|return\s+[1-9])"
    r"|\|\|\s*\{[^}]*\bdie\b"
    r"|\b(fails?|rc|FAILED|ok|errs?)\s*=\s*(1|true|false)\b"
    r"|\bfails\s*\+?=\s*1\b)"
)

OPENERS = re.compile(r"^\s*(if|case|while|for|until)\b")
CLOSERS = re.compile(r"^\s*(fi|esac|done)\b")


def strip_comments(lines: list[str]) -> list[str]:
    """Blank out full-line comments so they cannot satisfy or trigger a rule.

    A trailing comment is left alone: stripping it would need quote tracking, and getting
    that wrong is how a strip-pass swallows real code.
    """
    return ["" if ln.lstrip().startswith("#") else ln for ln in lines]


def _falls_through_to_nonzero(lines: list[str], depths: list[int], start: int) -> bool:
    """A printed failure may also be satisfied by a SHARED TERMINAL EXIT.

    `check-trace-summary-consistency.sh` is the worked example and it is CORRECT: its
    success branch exits 0 explicitly, then two independent failure branches each print
    their diagnosis, fall out of their `if`, and reach one `exit 1` at the end of the file.
    Requiring the exit INSIDE each branch would flag that script — and the first version of
    this guard did exactly that, reporting two false positives beside one real bug.

    So: satisfied when the LAST statement is a non-zero `exit` and no `exit 0` sits between
    the print and the end at depth 0, which would let control escape before reaching it.
    """
    body = [(i, ln) for i, ln in enumerate(lines) if ln.strip()]
    if not body:
        return False
    last_i, last = body[-1]
    if not re.match(r"^exit\s+[1-9]", last.strip()):
        return False
    for i in range(start + 1, last_i):
        if depths[i] == 0 and re.match(r"^\s*exit\s+0\b", lines[i]):
            return False
    return True


def p1_violations(lines: list[str]) -> list[tuple[int, str]]:
    """Every printed failure must reach a non-zero exit — in its branch or at the end."""
    out: list[tuple[int, str]] = []
    depth = 0
    depths = []
    for ln in lines:
        if OPENERS.match(ln):
            depth += 1
        elif CLOSERS.match(ln):
            depth = max(0, depth - 1)
        depths.append(depth)

    for i, ln in enumerate(lines):
        if not (PRINTS.match(ln) and FAILURE_MARK.search(ln)):
            continue
        here = depths[i]
        # The print's OWN line may carry the exit or the accumulator.
        satisfied = bool(SATISFIES.search(ln))
        for j in range(i + 1, len(lines)):
            # The branch has closed once we are shallower than where the print was.
            if depths[j] < here:
                break
            if SATISFIES.search(lines[j]):
                satisfied = True
                break
            # A NEW printed verdict at the same depth means we left the failure branch
            # (an `else` printing a pass, say) without ever exiting.
            if (
                depths[j] == here
                and PRINTS.match(lines[j])
                and "RESULT" in lines[j]
                and j != i
                and not FAILURE_MARK.search(lines[j])
            ):
                break
        if not satisfied and _falls_through_to_nonzero(lines, depths, i):
            satisfied = True
        if not satisfied:
            out.append((i + 1, ln.strip()[:100]))
    return out


def p2_last_statement(lines: list[str]) -> str | None:
    """The last executable statement must have a deterministic status.

    Returns a reason string when it does not, else None.

    `esac` / `fi` are ACCEPTED as terminal only when every arm of that construct exits —
    `check-deploy-provenance.sh` is the worked example and it is correct, so a rule that
    rejected a trailing `esac` outright would flag a good script and get switched off.
    """
    body = [ln for ln in lines if ln.strip()]
    if not body:
        return "the file is empty"
    last = body[-1].strip()
    if re.match(r"^exit\b", last):
        return None
    if last in ("fi", "esac", "done"):
        # Walk back to the construct's opener and require an exit in every arm.
        depth = 0
        arms_ok = True
        saw_arm = False
        for ln in reversed(body):
            s = ln.strip()
            if s in ("fi", "esac", "done"):
                depth += 1
                continue
            if OPENERS.match(ln):
                depth -= 1
                if depth == 0:
                    break
            if depth == 1 and re.match(r"^\s*(\w+\)|else|elif|\*\))", ln):
                saw_arm = True
        # Cheap sufficiency test: every `;;` arm and every else/then block ends in an exit.
        arm_bodies = re.split(
            r"\n\s*(?:;;|else|elif .*?then)\s*\n", "\n".join(body[-60:])
        )
        for ab in arm_bodies:
            if ab.strip() and not re.search(r"^\s*(exit\s+\d|die\b)", ab, re.MULTILINE):
                arms_ok = False
        if saw_arm and arms_ok:
            return None
        return (
            f"ends with `{last}` and not every arm of that construct exits — the status "
            "is whatever the last arm's last command returned"
        )
    return (
        f"the last statement is `{last[:70]}` — the exit status is an ACCIDENT of that "
        "line, not a verdict. Add an explicit `exit 0`."
    )


def _rel(path: Path) -> str:
    """Repo-relative when possible; the selftest writes to a temp dir outside ROOT."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_one(path: Path) -> list[str]:
    lines = strip_comments(path.read_text(encoding="utf-8").splitlines())
    errs = []
    for lineno, text in p1_violations(lines):
        errs.append(
            f"{_rel(path)}:{lineno} PRINTS A FAILURE AND DOES NOT EXIT:\n"
            f"      {text}\n"
            "      The caller reads the EXIT status. A printed ✗ that falls through to a "
            "zero exit is a\n      false GREEN the deploy banner will repeat."
        )
    why = p2_last_statement(lines)
    if why:
        errs.append(f"{_rel(path)}: {why}")
    return errs


def selftest() -> int:
    """Plant BOTH real bugs, verbatim in shape, and require a refusal for each."""
    import tempfile

    fails = 0

    def case(label: str, ok: bool, detail: str = "") -> None:
        nonlocal fails
        print(f"  {'✓' if ok else '✗'} {label}{(' — ' + detail) if detail else ''}")
        if not ok:
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)

        # 1. THE PROOF C SHAPE — prints ✗, falls through, exits 0.
        bad_c = d / "c.sh"
        bad_c.write_text(
            "#!/usr/bin/env bash\nset -uo pipefail\n"
            'if [[ "$A" -eq 0 ]]; then\n'
            '  echo "  RESULT: ✅ verified"\n'
            "else\n"
            '  echo "  RESULT: ✗ unexpected — GREEN should be exit 0"\n'
            "fi\n"
            'echo "===="\n'
        )
        errs = check_one(bad_c)
        case(
            "the Proof C shape (prints ✗, exits 0) REFUSES",
            any("PRINTS A FAILURE" in e for e in errs),
            f"got {len(errs)} error(s)",
        )

        # 2. THE PROOF E SHAPE — a trailing `&&` chain decides the status.
        bad_e = d / "e.sh"
        bad_e.write_text(
            "#!/usr/bin/env bash\n"
            'echo "✓ within threshold"\n'
            '[ "$X" = "$Y" ] && [ "$P" = "0" ] \\\n  && echo "  anchor set"\n'
        )
        errs = check_one(bad_e)
        case(
            "the Proof E shape (trailing && chain) REFUSES",
            any("last statement" in e for e in errs),
            f"got {len(errs)} error(s)",
        )

        # 3. THE CORRECT SIBLING must PASS — otherwise the guard refuses everything and
        #    gets switched off, which loses it entirely.
        good = d / "good.sh"
        good.write_text(
            "#!/usr/bin/env bash\n"
            'if [ "$A" -eq 0 ]; then\n'
            '  echo "  RESULT: OK"\n'
            "else\n"
            '  echo "  RESULT: FAIL -- inspect the JSON."\n'
            "  exit 1\n"
            "fi\n"
            "exit 0\n"
        )
        case(
            "the CORRECT shape passes (the check is not vacuous)", check_one(good) == []
        )

        # 4. A `die` satisfies it too — that is how gateway.sh's own inline proofs refuse.
        withdie = d / "die.sh"
        withdie.write_text(
            "#!/usr/bin/env bash\n"
            'if [ "$A" -ne 0 ]; then\n'
            '  echo "❌ FAILED to verify"\n'
            '  die "nope"\n'
            "fi\n"
            "exit 0\n"
        )
        case("a `die` satisfies the exit requirement", check_one(withdie) == [])

    if fails == 0:
        print(
            "\nSELFTEST PASSED — both REAL bugs refuse (a printed ✗ that exits 0, and a\n"
            "  trailing && chain deciding the status), and the correct shape still passes."
        )
        return 0
    print(f"\nSELFTEST FAILED — {fails} case(s).")
    return 1


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    if sys.argv[1:]:
        print(__doc__)
        return 2

    all_errs: list[str] = []
    checked = 0
    for rel in PROOFS:
        p = ROOT / rel
        if not p.exists():
            print(
                f"✗ CANNOT DETERMINE — {rel} is named in this guard but does not exist."
            )
            return 2
        checked += 1
        all_errs.extend(check_one(p))

    if all_errs:
        print("✗ A PROOF'S PRINTED VERDICT AND ITS EXIT VERDICT CAN DISAGREE:\n")
        for e in all_errs:
            print("  " + e + "\n")
        print(
            "  `scripts/deploy/gateway.sh` decides ROLLBACK on the exit status and shows a\n"
            "  human the printed one. When they disagree, either a healthy deploy is\n"
            "  reverted or a broken one prints ✅ DEPLOY GREEN."
        )
        return 1
    print(
        f"OK — {checked} deploy-path proof(s); printed and exit verdicts cannot disagree."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

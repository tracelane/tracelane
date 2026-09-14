#!/usr/bin/env python3
"""A deploy gate must read COVERAGE, and a deploy record must not assert coverage it lacks.

WHY THIS EXISTS — SRE audit rows S4 and S5, 2026-09-04, and it is one guard because they
are one defect wearing two hats: a deploy script that reports the query returned rather
than that the thing is true.

  * **S4 / B-295 — `scripts/deploy/gateway.sh` gated on a CI *conclusion*.** Private-repo
    CI skips its substantive jobs on a `push`, so a run finishes `completed/success`
    having compiled nothing and tested nothing. Founder ruling R206 removed exactly this
    from the sibling `web.sh` on 2026-08-27 and LEFT THE SURVIVOR in `gateway.sh`; the
    repo filed it as B-295 the same day and it sat open for eight days. On 2026-09-04 it
    produced a false green on a REAL deploy — `CI green for f6d00ab1` for the same run
    `scripts/ops/ci-status.sh` calls `CANNOT DETERMINE — 15 of 16 skipped`.

  * **S5 — `scripts/deploy/web.sh` printed `all proofs passed` unconditionally**, including
    when Proof D (the only authenticated-render proof, and per the internal ledger one that
    has never actually run) was skipped for want of `PROD_STORAGE_STATE`. Every web deploy
    record this repo holds therefore asserts coverage that did not exist.

**THE CLASS, which is why a guard and not two edits.** R206 fixed one of two siblings by
hand; eight days later the other one lied on a live deploy. A fix applied to the instance
does not survive the next sibling — `scripts/deploy/site.sh` is a third script today and
has no CI gate at all. This is the graduation ladder in CLAUDE.md §12: the incident earned
a rule, the rule earns an executable gate, and the gate is what actually holds.

WHAT IT CHECKS, and every property is decidable from the text:

  P1  A deploy script that HAS a CI gate (it mentions `SKIP_CI_CHECK`) takes its verdict
      from `scripts/ops/ci-status.sh` and nowhere else. A live `completed/success` test, or
      a `gh run list` whose `.conclusion` is compared, is the S4 defect by definition.
  P2  A line claiming complete coverage ("all proofs passed") must be preceded by a READ of
      a skip ledger. A summary that cannot see a skip cannot be conditioned on one.
  P3  Every skip a script RECORDS is READ BACK. A `*_SKIPPED` flag assigned and never read
      is B-189's shape — computed, printed, and never consulted — and it is exactly how
      `gateway.sh`'s hand-maintained three-flag list would drift when a fourth proof lands.
  P4  For scripts using the ledger-helper form, there are at least as many ledger calls as
      there are `say "Proof …"` announcements, so a newly announced proof cannot reach the
      summary unrecorded.

**ITS HONEST LIMIT, and the difference is the point.** This proves the summary is WIRED to
the ledger. It cannot prove the ledger is COMPLETE: a proof site that simply forgets to
call `proof_skipped` on its skip path is invisible here, and P4 only counts announcements,
so a proof announced with a bare `echo` slips past. That half is review, not machinery —
the same limit `check-spec-anchors.py` states about anchors resolving versus being true.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

# A line whose first non-space character is `#` is documentation, not behaviour. Both
# deploy scripts quote their own removed defect verbatim in a comment block — the guard
# must read what the shell reads.
COMMENT = re.compile(r"^\s*#")

CONCLUSION_TEST = re.compile(r"completed/success|\.conclusion\b")
COVERAGE_CLAIM = re.compile(r"all proofs (?:passed|green)", re.IGNORECASE)
SKIP_ASSIGN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*_SKIPPED)\s*=")
SKIP_READ = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*_SKIPPED)\b")
LEDGER_READ = re.compile(r"\$\{?(?:PROOFS_SKIPPED|_skipped)\b")
LEDGER_CALL = re.compile(r"\bproof_(?:ran|skipped)\b")
LEDGER_DEF = re.compile(r"^\s*proof_(?:ran|skipped)\s*\(\)")
# A line that ASSIGNS to the ledger is a write, never a read. Both the helper bodies
# (`PROOFS_SKIPPED="${PROOFS_SKIPPED}…"`) and gateway.sh's appends
# (`_skipped="${_skipped}F …"`) mention the variable while adding to it, and counting
# either as "the summary consulted the ledger" would let the S5 defect back through
# untouched — the selftest caught exactly that on this guard's first run.
LEDGER_WRITE = re.compile(r"\b(?:PROOFS_SKIPPED|_skipped)\s*=")
PROOF_ANNOUNCE = re.compile(r'say\s+"Proof\s')


def live_lines(text: str) -> list[tuple[int, str]]:
    """(1-indexed lineno, line) for every line the shell actually executes."""
    return [
        (i, ln) for i, ln in enumerate(text.splitlines(), 1) if not COMMENT.match(ln)
    ]


def check_script(path: Path, text: str) -> list[str]:
    live = live_lines(text)
    body = "\n".join(ln for _, ln in live)
    problems: list[str] = []

    # ── P1 — one source for the CI verdict ──────────────────────────────────────
    if "SKIP_CI_CHECK" in body:
        if "ci-status.sh" not in body:
            problems.append(
                f"{path.name}: has a CI gate (SKIP_CI_CHECK) but never invokes "
                f"scripts/ops/ci-status.sh — the verdict has no sanctioned source (S4/B-295)"
            )
        for lineno, ln in live:
            if CONCLUSION_TEST.search(ln):
                problems.append(
                    f"{path.name}:{lineno}: decides CI state from a run CONCLUSION "
                    f"({ln.strip()[:70]!r}) — conclusion is NOT coverage; a private push "
                    f"finishes completed/success with every substantive job skipped (S4/B-295)"
                )

    # ── P2 — a coverage claim must be guarded by a ledger read ──────────────────
    first_ledger_read = next(
        (n for n, ln in live if LEDGER_READ.search(ln) and not LEDGER_WRITE.search(ln)),
        None,
    )
    for lineno, ln in live:
        if COVERAGE_CLAIM.search(ln) and (
            first_ledger_read is None or first_ledger_read > lineno
        ):
            problems.append(
                f"{path.name}:{lineno}: claims complete coverage with no skip ledger "
                f"read before it — the deploy record asserts proofs that may have been "
                f"SKIPPED (S5)"
            )

    # ── P3 — every recorded skip is read back ───────────────────────────────────
    assigned = {m.group(1) for _, ln in live for m in SKIP_ASSIGN.finditer(ln)}
    read = {m.group(1) for _, ln in live for m in SKIP_READ.finditer(ln)}
    for name in sorted(assigned - read):
        problems.append(
            f"{path.name}: sets ${name} and never reads it — a skip that reaches no "
            f"summary is a skip nobody is told about (B-189's shape)"
        )
    if LEDGER_CALL.search(body) and not re.search(r"\$\{?PROOFS_SKIPPED\b", body):
        problems.append(
            f"{path.name}: calls proof_skipped but never reads $PROOFS_SKIPPED — the "
            f"ledger is written and never rendered (S5)"
        )

    # ── P4 — announced proofs are ledgered (helper-form scripts only) ───────────
    if any(LEDGER_DEF.match(ln) for _, ln in live):
        announced = sum(1 for _, ln in live if PROOF_ANNOUNCE.search(ln))
        calls = sum(
            1 for _, ln in live if LEDGER_CALL.search(ln) and not LEDGER_DEF.match(ln)
        )
        if calls < announced:
            problems.append(
                f"{path.name}: announces {announced} proof(s) but has only {calls} ledger "
                f"call(s) — a proof can reach the summary unrecorded (S5)"
            )
    return problems


def scan(root: Path) -> list[str]:
    deploy = root / "scripts" / "deploy"
    if not deploy.is_dir():
        return [
            f"{deploy} does not exist — this guard has nothing to check, which is not a pass"
        ]
    problems: list[str] = []
    for path in sorted(deploy.glob("*.sh")):
        problems.extend(check_script(path, path.read_text(encoding="utf-8")))
    return problems


# ── selftest ────────────────────────────────────────────────────────────────────
CLEAN = """#!/usr/bin/env bash
set -uo pipefail
PROOFS_RAN=""
PROOFS_SKIPPED=""
proof_ran()     { PROOFS_RAN="${PROOFS_RAN}${1}, "; }
proof_skipped() { PROOFS_SKIPPED="${PROOFS_SKIPPED}${1} - ${2}, "; }
if [ "${SKIP_CI_CHECK:-0}" != "1" ]; then
  bash "$ROOT/scripts/ops/ci-status.sh" "$SHA"; ci_rc=$?
  case "$ci_rc" in 0) proof_ran "CI verdict" ;; *) die "not green" ;; esac
fi
say "Proof A - a thing"
proof_ran "A"
if [ -n "$PROOFS_SKIPPED" ]; then
  say "coverage INCOMPLETE: ${PROOFS_SKIPPED%, }"
else
  say "all proofs passed"
fi
"""


def _case(tmp: Path, name: str, body: str) -> list[str]:
    d = tmp / name / "scripts" / "deploy"
    d.mkdir(parents=True)
    (d / "x.sh").write_text(body, encoding="utf-8")
    return scan(tmp / name)


def selftest() -> int:
    fails = 0

    def expect(label: str, problems: list[str], want: str | None) -> None:
        nonlocal fails
        if want is None:
            if problems:
                print(f"  ✗ {label}: expected clean, got {problems}")
                fails += 1
            else:
                print(f"  ✓ {label}")
            return
        if any(want in p for p in problems):
            print(f"  ✓ {label}")
        else:
            print(
                f"  ✗ {label}: expected a problem containing {want!r}, got {problems}"
            )
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        expect(
            "a correctly-gated deploy script passes", _case(tmp, "clean", CLEAN), None
        )

        # S4, exactly as it stood in gateway.sh until 2026-09-04.
        expect(
            "a CI gate reading a run CONCLUSION is refused",
            _case(
                tmp,
                "s4",
                CLEAN.replace(
                    'case "$ci_rc" in 0) proof_ran "CI verdict" ;; *) die "not green" ;; esac',
                    'case "$st" in completed/success) echo "CI green" ;; esac',
                ),
            ),
            "conclusion is NOT coverage",
        )

        # S4b — a CI gate with no sanctioned source at all.
        expect(
            "a CI gate that never consults ci-status.sh is refused",
            _case(
                tmp,
                "s4b",
                CLEAN.replace('bash "$ROOT/scripts/ops/ci-status.sh" "$SHA"; ', ""),
            ),
            "never invokes scripts/ops/ci-status.sh",
        )

        # S5, exactly as it stood in web.sh until 2026-09-04.
        expect(
            "an unconditional 'all proofs passed' is refused",
            _case(
                tmp,
                "s5",
                CLEAN.replace(
                    'if [ -n "$PROOFS_SKIPPED" ]; then\n'
                    '  say "coverage INCOMPLETE: ${PROOFS_SKIPPED%, }"\n'
                    "else\n"
                    '  say "all proofs passed"\n'
                    "fi\n",
                    'say "all proofs passed"\n',
                ),
            ),
            "claims complete coverage with no skip ledger read",
        )

        # P3 — the drift case: a flag recorded and never rendered.
        expect(
            "a *_SKIPPED flag that is set and never read is refused",
            _case(tmp, "p3", CLEAN.replace('proof_ran "A"', "PROOF_A_SKIPPED=1")),
            "never reads it",
        )

        # P4 — a proof announced after the ledger exists but never recorded.
        expect(
            "a proof announced but not ledgered is refused",
            _case(
                tmp,
                "p4",
                CLEAN.replace(
                    'say "Proof A - a thing"\nproof_ran "A"',
                    'say "Proof A - a thing"\nsay "Proof B - another"\nsay "Proof C - a third"',
                ),
            ),
            "ledger call",
        )

        # The comment-blindness property both real scripts depend on: each of them
        # quotes its own removed defect verbatim in a comment block, and a guard that
        # read comments would refuse the very fix it exists to require.
        expect(
            "the removed defect quoted in a COMMENT does not trip the guard",
            _case(
                tmp,
                "comment",
                CLEAN.replace(
                    "set -uo pipefail",
                    'set -uo pipefail\n# This used to read: case "$st" in completed/success) …\n'
                    '# and it printed "all proofs passed" unconditionally.',
                ),
            ),
            None,
        )

    if fails:
        print(f"deploy-gate-honesty selftest FAILED — {fails} case(s).")
        return 1
    print("deploy-gate-honesty selftest PASSED.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        if argv[1] == "--selftest":
            return selftest()
        print(f"check-deploy-gate-honesty: unknown option: {argv[1]}", file=sys.stderr)
        return 2

    problems = scan(Path(__file__).resolve().parents[2])
    if not problems:
        return 0
    print()
    print("  ✗ DEPLOY GATE / DEPLOY RECORD HONESTY:")
    for p in problems:
        print(f"      {p}")
    print()
    print("  A deploy gate must read COVERAGE, not a run's conclusion:")
    print('      bash "$ROOT/scripts/ops/ci-status.sh" "$SHA"; ci_rc=$?')
    print('      case "$ci_rc" in 0) : ;; 1) die … ;; 2) die … ;; *) die … ;; esac')
    print("  and a summary may only claim complete coverage after reading the skip")
    print("  ledger it records into. See scripts/deploy/web.sh for the worked shape.")
    print()
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

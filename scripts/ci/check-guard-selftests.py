#!/usr/bin/env python3
"""Every guard `verify-all.sh` invokes must have a selftest that actually proves something.

WHY. 20 of the 44 scripts under scripts/{ci,hooks,export} silently ACCEPTED `--selftest`
and exited 0 having proven nothing — no argv parsing at all, so the flag ran the ordinary
guard and reported PASS. Nobody passed them the flag, so it was a latent trap rather than
an active lie: the moment someone added `run "X selftest" python3 scripts/ci/X.py
--selftest` to verify-all.sh it would print PASS forever, and the repo would carry a
falsification claim that had never falsified anything.

This is the meta-gate. It does not trust that a selftest exists; it establishes that the
script can tell one flag from another, which is the precondition for `--selftest` to mean
anything at all.

THE DISCRIMINATOR — this is the whole idea. For each guard:

    <script> --selftest              must exit 0     (the selftest passes)
    <script> --<nonsense-flag>       must exit NON-0 (argv is genuinely parsed)

The second probe is what makes the first one evidence. A script with no argv handling
returns 0 for BOTH, and that pair is indistinguishable from a passing selftest — which is
exactly how 20 scripts looked green. A script that rejects nonsense but accepts
`--selftest` has, at minimum, been told the difference on purpose.

HONEST LIMIT — read before trusting a pass. This proves a selftest RUNS and that the flag
is REAL. It cannot prove the selftest is *good*: a script could parse `--selftest`, print
"✓ everything fine" and exit 0 without planting anything. No machine reads a selftest and
decides whether its assertions bite. What defends that is the contract in the guards
themselves — plant a violation, assert it is caught, assert a clean input passes, restore
state — and a human reading the diff. This gate closes the mechanical hole; the judgement
stays human. Same limit the promotion gate states about the adversarial pass.

USAGE
  check-guard-selftests.py             # every scripts/** guard invoked by verify-all.sh
  check-guard-selftests.py --selftest  # prove the meta-gate itself blocks
  check-guard-selftests.py --list      # show what it would check, run nothing
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFY_ALL = ROOT / "scripts" / "verify-all.sh"

# `run "label" <runner> <script> [args...]` — the only shape verify-all.sh uses.
RE_RUN = re.compile(r'^\s*run\s+"[^"]*"\s+(.*)$')

# A nonsense flag no guard could legitimately implement. If a script exits 0 for THIS,
# it is not parsing argv and its `--selftest` result is meaningless.
BOGUS = "--tracelane-meta-gate-nonsense-flag"

# Guards that cannot be selftested offline. Each needs a REASON, and each is still
# required to REJECT the bogus flag — being un-selftestable is not a licence to ignore
# argv. Empty today; an entry here is a claim someone must justify in review.
UNSELFTESTABLE: dict[str, str] = {}


def invoked_guards(verify_all: Path) -> list[tuple[str, list[str]]]:
    """Distinct scripts/** commands verify-all.sh runs, as (script_path, argv_prefix)."""
    out: dict[str, list[str]] = {}
    for line in verify_all.read_text(encoding="utf-8").splitlines():
        m = RE_RUN.match(line)
        if not m:
            continue
        parts = m.group(1).split()
        # Find the scripts/** token; the tokens before it are the runner (python3/bash).
        idx = next((i for i, p in enumerate(parts) if p.startswith("scripts/")), None)
        if idx is None:
            continue  # cargo / pnpm / node — not one of our guard scripts
        script = parts[idx]
        if script.endswith((".py", ".sh")):
            out.setdefault(script, parts[:idx])
    return sorted(out.items())


def runner_for(script: str, prefix: list[str]) -> list[str]:
    if prefix:
        return prefix
    return ["python3"] if script.endswith(".py") else ["bash"]


def probe(cmd: list[str], cwd: Path, timeout: int = 300) -> int:
    try:
        # check=False is the point: a NON-ZERO exit is the expected result for the
        # bogus-flag probe, so raising on it would invert the whole gate.
        p = subprocess.run(
            cmd, cwd=cwd, capture_output=True, timeout=timeout, check=False
        )
        return p.returncode
    except subprocess.TimeoutExpired:
        return 124


def check(verify_all: Path = VERIFY_ALL, cwd: Path = ROOT) -> tuple[int, list[str]]:
    failures: list[str] = []
    guards = invoked_guards(verify_all)
    for script, prefix in guards:
        if not (cwd / script).exists():
            failures.append(f"{script}: invoked by verify-all.sh but does not exist")
            continue
        run = runner_for(script, prefix)

        # Probe 1 — argv must be parsed. This is what makes probe 2 evidence.
        rc_bogus = probe([*run, script, BOGUS], cwd)
        if rc_bogus == 0:
            failures.append(
                f"{script}: exits 0 for `{BOGUS}` — it does not parse argv, so a "
                "`--selftest` pass would prove NOTHING"
            )
            continue

        if script in UNSELFTESTABLE:
            continue  # rejects unknown flags; selftest waived with a recorded reason

        # Probe 2 — the selftest must actually pass.
        rc_self = probe([*run, script, "--selftest"], cwd)
        if rc_self != 0:
            failures.append(f"{script}: `--selftest` exited {rc_self} (expected 0)")
    return len(guards), failures


def selftest() -> int:
    """Falsify the meta-gate: it must FAIL on a guard that accepts everything."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "scripts" / "ci").mkdir(parents=True)

        # A well-behaved guard: rejects unknown flags, real --selftest.
        good = td / "scripts" / "ci" / "good.py"
        good.write_text(
            "import sys\n"
            "if '--selftest' in sys.argv: print('ok'); sys.exit(0)\n"
            "if len(sys.argv) > 1: sys.exit(2)\n"
            "sys.exit(0)\n"
        )
        # THE BUG SHAPE: no argv handling at all — exits 0 for anything.
        liar = td / "scripts" / "ci" / "liar.sh"
        liar.write_text("#!/usr/bin/env bash\necho 'guard OK'\nexit 0\n")
        # Parses argv, but its selftest genuinely fails.
        broken = td / "scripts" / "ci" / "broken.py"
        broken.write_text(
            "import sys\n"
            "if '--selftest' in sys.argv: print('nope'); sys.exit(1)\n"
            "if len(sys.argv) > 1: sys.exit(2)\n"
            "sys.exit(0)\n"
        )

        def va(*lines: str) -> Path:
            p = td / "verify-all.sh"
            p.write_text("\n".join(lines) + "\n")
            return p

        n, f = check(va('    run "good" python3 scripts/ci/good.py'), td)
        assert n == 1 and not f, f"selftest: a well-behaved guard must PASS, got {f}"
        print("✓ selftest: a guard with a real selftest passes")

        n, f = check(va('    run "liar" bash scripts/ci/liar.sh'), td)
        assert len(f) == 1 and "does not parse argv" in f[0], f"got {f}"
        print(
            "✓ selftest: a guard that accepts ANY flag is caught (the 20-script shape)"
        )

        n, f = check(va('    run "broken" python3 scripts/ci/broken.py'), td)
        assert len(f) == 1 and "exited 1" in f[0], f"got {f}"
        print("✓ selftest: a guard whose selftest FAILS is caught")

        n, f = check(va('    run "gone" python3 scripts/ci/gone.py'), td)
        assert len(f) == 1 and "does not exist" in f[0], f"got {f}"
        print("✓ selftest: a guard invoked but missing is caught")

        # The parser must not silently drop guards — if it did, everything "passes".
        n, f = check(
            va(
                '    run "good" python3 scripts/ci/good.py',
                '    run "liar" bash scripts/ci/liar.sh',
                '    run "cargo" cargo fmt --check',
                '    run "pnpm" pnpm lint',
            ),
            td,
        )
        assert n == 2, f"selftest: expected exactly 2 guard scripts parsed, got {n}"
        assert len(f) == 1, f"got {f}"
        print(
            "✓ selftest: non-script commands (cargo/pnpm) are ignored, guards are not"
        )

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--selftest", action="store_true", help="prove the meta-gate blocks"
    )
    ap.add_argument("--list", action="store_true", help="list what would be checked")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.list:
        for s, p in invoked_guards(VERIFY_ALL):
            print(f"  {' '.join(runner_for(s, p))} {s}")
        return 0

    n, failures = check()
    for f in failures:
        print(f"FAIL {f}")
    if failures:
        print(
            f"\n{len(failures)} of {n} guard(s) invoked by verify-all.sh cannot prove they "
            "block.\nA guard whose falsification has never been observed is not a guard — "
            "it is a\nscript that has only ever been seen agreeing with the repo."
        )
        return 1
    print(f"guard selftests: {n} guard(s) invoked by verify-all.sh, all provably armed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

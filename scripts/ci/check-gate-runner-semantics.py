#!/usr/bin/env python3
"""The gate's own runners do what their names claim — and a CRITICAL advisory blocks.

WHY THIS EXISTS (B-373, 2026-09-10). `pnpm audit` had been wired into
`scripts/verify-all.sh` for months and still missed an *unauthenticated remote code
execution* in `next` 15.5.21 on the production dashboard. Nothing was broken in the
scan: it ran, it found it, it printed it. The defect was the WIRING — it reached the
gate through `run_advisory`, which records WARN and never touches `overall`, so every
green run in this repo's history was green with a live critical RCE in it.

That is the `green-while-broken` shape at the level of the gate's own plumbing, and it
is invisible to every other guard here: they check what the gate RUNS, never what the
gate DOES with a failure. So this checks three things nothing else does.

  1. RUNNER SEMANTICS — `run_blocking_scan` fails the gate on a real finding, WARNs on
     "the registry was unreachable so nothing was scanned", and passes on a clean scan;
     `_audit_with_retry` passes a real finding's own exit code through untouched and
     returns the CANNOT-DETERMINE sentinel only when it genuinely could not look.
     Driven against the REAL function bytes cut out of verify-all.sh — a harness
     carrying its own copy of the code under test proves only that the copy works
     (`docs/reference/TRAPS.md` §38, the circular-selftest class).
  2. THE WIRING — a `--audit-level=critical` scan exists, and it is NOT routed through
     `run_advisory`. This is the specific regression that would re-open B-373: not
     deleting the step, but quietly demoting it back to advisory, which looks like
     noise reduction in a diff and restores the exact hole.
  3. THE MUTE LIST — `pnpm.auditConfig.ignoreGhsas` in the root package.json now
     silences a gate that BLOCKS, which it never did before. Measured 2026-09-10 by
     emptying the list and re-running: it is suppressing `GHSA-5xrq-8626-4rwp`, a
     **CVSS 9.8 critical**. An entry there is therefore a security decision, and each
     one has to carry a written reason AND a machine-checked precondition — the fact
     that makes it safe, asserted every run, so the mute dies the moment the fact
     does. A third entry was found STALE the same day (`GHSA-mh99-v99m-4gvg`,
     brace-expansion: both resolved copies, 2.1.4 and 5.0.9, are above their patched
     versions) and was removed rather than left muting nothing.

HONEST LIMIT. This proves the runner does the right thing with an exit code, that the
critical scan is wired to block, and that every mute carries a reason whose stated
precondition still holds. It cannot prove `pnpm audit` itself reports every advisory,
it cannot judge whether a written reason is a GOOD one, and it says nothing about
severities below critical — those are advisory here by design and block in the nightly
under TRACELANE_GATE_STRICT_NETWORK=1.

USAGE
  check-gate-runner-semantics.py            # assert all three properties
  check-gate-runner-semantics.py --selftest # prove each assertion BLOCKS
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFY_ALL = ROOT / "scripts" / "verify-all.sh"
PACKAGE_JSON = ROOT / "package.json"
LOCKFILE = ROOT / "pnpm-lock.yaml"

# Functions lifted verbatim out of verify-all.sh, in dependency order.
NEEDED_FUNCS = [
    "_area_active",
    "run",
    "_audit_with_retry",
    "run_advisory",
    "run_blocking_scan",
]
SENTINEL_DECL = "readonly AUDIT_CANNOT_DETERMINE="

RE_STEP = re.compile(r'^\s*(run|run_advisory|run_blocking_scan)\s+"([^"]*)"\s+(.*)$')


def extract_func(text: str, name: str) -> str | None:
    """The literal source of `name() { ... }` — from its header line to a bare `}`."""
    lines = text.splitlines()
    header = f"{name}() {{"
    for i, line in enumerate(lines):
        if line == header:
            for j in range(i + 1, len(lines)):
                if lines[j] == "}":
                    return "\n".join(lines[i : j + 1])
            return None
    return None


def extract_sentinel(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith(SENTINEL_DECL):
            return line
    return None


# ── property 1: runner semantics ────────────────────────────────────────────────
# Each case is (label, the command the runner is handed, expected STATUSES[0],
# expected `overall`, extra env). The commands are synthetic on purpose: the subject
# is the RUNNER, not pnpm.
# EVERY case pins TRACELANE_GATE_STRICT_NETWORK explicitly. The first version set it
# only for the strict case and let the others INHERIT it — so under the nightly's
# job-level `TRACELANE_GATE_STRICT_NETWORK=1` the "WARN" cases correctly produced
# FAIL(90) and this selftest went red on its own configuration (nightly run
# 34575067159, 2026-09-11). A test that does not own its inputs is measuring the
# environment, not the code.
_LAX = {"TRACELANE_GATE_STRICT_NETWORK": "0"}
_STRICT = {"TRACELANE_GATE_STRICT_NETWORK": "1"}
CASES = [
    ("a real finding FAILS and sets overall=1", "exit 1", "FAIL(1)", 1, _LAX),
    ("registry unreachable WARNs, overall stays 0", "exit 90", "WARN", 0, _LAX),
    ("a clean scan PASSES", "exit 0", "PASS", 0, _LAX),
    (
        "under STRICT_NETWORK even CANNOT-DETERMINE blocks",
        "exit 90",
        "FAIL(90)",
        1,
        _STRICT,
    ),
    (
        "under STRICT_NETWORK a real finding still FAILS",
        "exit 1",
        "FAIL(1)",
        1,
        _STRICT,
    ),
]

HARNESS = """set -uo pipefail
EXPLAIN=0; SCOPED=0; AREA=ALWAYS; overall=0
declare -a CHANGED_BUCKETS=(ALWAYS)
declare -a NAMES=() STATUSES=() DURATIONS=() SCOPED_OUT=() WARNED=()
__FUNCS__
run_blocking_scan "probe" bash -c '__CMD__' >/dev/null 2>&1
printf 'STATUS=%s OVERALL=%s\\n' "${STATUSES[0]:-<none>}" "$overall"
"""

RETRY_HARNESS = """set -uo pipefail
__FUNCS__
_audit_with_retry "probe" bash -c '__CMD__' >/dev/null 2>&1
printf 'RC=%s\\n' "$?"
"""


def _funcs_blob(text: str) -> tuple[str, list[str]]:
    """The extracted bash, plus any extraction failures."""
    problems: list[str] = []
    parts: list[str] = []
    sentinel = extract_sentinel(text)
    if sentinel is None:
        problems.append(
            f"no `{SENTINEL_DECL}<n>` declaration in verify-all.sh — without the "
            f"sentinel, 'the registry was unreachable' and 'we found a critical' are "
            f"the same exit code and the runner cannot tell them apart"
        )
    else:
        parts.append(sentinel)
    for name in NEEDED_FUNCS:
        src = extract_func(text, name)
        if src is None:
            problems.append(f"could not extract `{name}()` from verify-all.sh")
        else:
            parts.append(src)
    return "\n".join(parts), problems


def _bash(script: str, env_extra: dict[str, str]) -> str:
    import os

    env = dict(os.environ)
    env.update(env_extra)
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(script)
        path = fh.name
    try:
        out = subprocess.run(
            ["bash", path],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )
        return out.stdout.strip()
    finally:
        Path(path).unlink(missing_ok=True)


def check_semantics(text: str) -> list[str]:
    blob, failures = _funcs_blob(text)
    if failures:
        return failures

    for label, cmd, want_status, want_overall, env in CASES:
        script = HARNESS.replace("__FUNCS__", blob).replace("__CMD__", cmd)
        got = _bash(script, env)
        want = f"STATUS={want_status} OVERALL={want_overall}"
        if got != want:
            failures.append(
                f"run_blocking_scan — {label}: expected {want!r}, got {got!r}"
            )

    # `_audit_with_retry` must not launder a real finding into the sentinel, and must
    # not report a real exit code when it never reached the registry.
    for label, cmd, want in [
        (
            "a real finding's exit code passes through untouched",
            'echo "1 critical"; exit 1',
            "RC=1",
        ),
        (
            "an unreachable registry returns the CANNOT-DETERMINE sentinel",
            "echo ERR_SOCKET_TIMEOUT >&2; exit 1",
            "RC=90",
        ),
    ]:
        script = RETRY_HARNESS.replace("__FUNCS__", blob).replace("__CMD__", cmd)
        got = _bash(script, {})
        if got != want:
            failures.append(
                f"_audit_with_retry — {label}: expected {want!r}, got {got!r}"
            )

    return failures


# ── property 2: the wiring ──────────────────────────────────────────────────────
CRITICAL_FLAG = "--audit-level=critical"


def check_wiring(text: str) -> list[str]:
    failures: list[str] = []
    steps = [RE_STEP.match(line) for line in text.splitlines()]
    crit = [
        (m.group(1), m.group(2)) for m in steps if m and CRITICAL_FLAG in m.group(3)
    ]

    if not crit:
        return [
            (
                f"no step in verify-all.sh runs a scan with {CRITICAL_FLAG}. B-373: a "
                f"critical advisory has to fail this gate, and the only npm audit "
                f"wired here was `--audit-level=high` through run_advisory, which "
                f"cannot fail anything."
            )
        ]
    for runner, label in crit:
        if runner != "run_blocking_scan":
            failures.append(
                f"{label!r} runs {CRITICAL_FLAG} through `{runner}` — that records "
                f"{'WARN and never touches `overall`' if runner == 'run_advisory' else 'the wrong semantics'}"
                f", so a critical advisory would not fail the gate. This is the exact "
                f"wiring that let an unauthenticated RCE sit green (B-373)."
            )
    return failures


# ── property 3: the mute list ───────────────────────────────────────────────────
# `pnpm.auditConfig.ignoreGhsas` silences `pnpm audit` — including the CRITICAL scan
# that now blocks. Every entry needs a reason a reader can check AND a precondition a
# machine re-checks each run, because the reason is only true while some fact stays
# true. `precondition` returns None when it holds, or the sentence that says it broke.


def _importers_block() -> str:
    """The `importers:` section of pnpm-lock.yaml — what each workspace ACTUALLY declares."""
    text = LOCKFILE.read_text(encoding="utf-8")
    i = text.find("\nimporters:")
    if i < 0:
        return ""
    j = text.find("\npackages:", i)
    return text[i : j if j > 0 else len(text)]


def _vitest_ui_absent() -> str | None:
    """GHSA-5xrq-8626-4rwp only fires when the Vitest UI server can run at all."""
    if "@vitest/ui" in _importers_block():
        return (
            "`@vitest/ui` is now a declared dependency of a workspace. The whole reason "
            "this CVSS 9.8 is muted is that the UI server cannot start without it — "
            "that reason is gone. Bump vitest past 3.2.6 or drop the UI."
        )
    return None


def _vitest_is_dev_only() -> str | None:
    """The vulnerable `vite` is reached ONLY through vitest, and vitest is a dev tool."""
    block = _importers_block()
    # Inside an importer, `dependencies:` is the runtime tree and `devDependencies:`
    # the dev one. A `vitest:` entry under the former makes the dev-only claim false.
    section: str | None = None
    for line in block.splitlines():
        stripped = line.strip()
        if stripped in ("dependencies:", "devDependencies:", "optionalDependencies:"):
            section = stripped[:-1]
        elif stripped.startswith("vitest:") and section == "dependencies":
            return (
                "`vitest` appears under a RUNTIME `dependencies:` block in "
                "pnpm-lock.yaml. Every path to the vulnerable `vite@5.4.21` runs "
                "through vitest, and this mute rests on that whole subtree being "
                "dev-only. It is not any more."
            )
    return None


AUDIT_IGNORE_JUSTIFICATIONS = {
    "GHSA-5xrq-8626-4rwp": (
        (
            "CRITICAL, CVSS 9.8 — vitest: arbitrary file read+execute WHEN THE VITEST UI "
            "SERVER IS LISTENING. `vitest@2.1.9` is a devDependency of six workspaces, and "
            "`@vitest/ui` — the package the attack needs — is NOT installed: it appears in "
            "pnpm-lock.yaml only as an OPTIONAL PEER of vitest, never in `importers:`. "
            "FOUNDER RULING R126 (2026-08-24) is NO BUMP: the first fix on our line is "
            "3.2.6, a 2.x -> 3.x major across six packages for a dev-only test runner "
            "whose exploit precondition we never meet. Tracked as VITEST-MAJOR in "
            "the founder tracker (internal); the same ignore, with the same reasoning, "
            "is mirrored in osv-scanner.toml and .grype.yaml. Re-verified 2026-09-10 by "
            "emptying ignoreGhsas and re-running the audit — this is the ONE critical it "
            "suppresses."
        ),
        _vitest_ui_absent,
    ),
    "GHSA-fx2h-pf6j-xcff": (
        (
            "HIGH — vite `server.fs.deny` bypass. Every path the audit reports goes "
            "`<workspace> > vitest@2.1.9 > … > vite@5.4.21`, so it is the dev test runner's "
            "own vite and never a server we run or ship. apps/site's vite is 8.3.0, above "
            "that branch's 8.0.16 fix. NOTE, and this corrects the reason recorded when the "
            "mute was added: the old justification said 5.x was OUTSIDE the vulnerable "
            "range. The advisory's range for that branch is `<= 6.4.2` with NO lower bound, "
            "so 5.4.21 IS inside it. The mute stands on dev-only reachability, which is "
            "true; it did not stand on the range, which was not."
        ),
        _vitest_is_dev_only,
    ),
}


def check_audit_ignores(
    listed: set[str] | None = None,
    justifications: dict | None = None,
) -> list[str]:
    """`listed`/`justifications` are injectable so the selftest can drive real cases."""
    failures: list[str] = []
    justifications = (
        AUDIT_IGNORE_JUSTIFICATIONS if justifications is None else justifications
    )
    if listed is None:
        try:
            pkg = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return [f"could not read {PACKAGE_JSON.name}: {exc}"]
        listed = set(pkg.get("pnpm", {}).get("auditConfig", {}).get("ignoreGhsas", []))
    known = set(justifications)

    for ghsa in sorted(listed - known):
        failures.append(
            f"{ghsa} is muted in package.json with no justification. An ignoreGhsas "
            f"entry now silences a gate that BLOCKS — record why it is safe in "
            f"AUDIT_IGNORE_JUSTIFICATIONS, with a precondition, or remove the mute."
        )
    for ghsa in sorted(known - listed):
        failures.append(
            f"{ghsa} carries a justification here but is no longer muted in "
            f"package.json. Delete the justification — a reason for a decision that "
            f"was reversed is the doc-vs-code defect CLAUDE.md §17 is about."
        )
    for ghsa in sorted(listed & known):
        _reason, precondition = justifications[ghsa]
        broken = precondition()
        if broken:
            failures.append(
                f"{ghsa}: its stated precondition no longer holds — {broken}"
            )
    return failures


def check(text: str) -> list[str]:
    return check_wiring(text) + check_audit_ignores() + check_semantics(text)


# ── selftest ────────────────────────────────────────────────────────────────────
def selftest() -> int:
    """Each assertion must BLOCK. A guard nobody has watched fail is decorative."""
    real = VERIFY_ALL.read_text(encoding="utf-8")

    cases: list[tuple[str, str, bool]] = [
        ("the real verify-all.sh passes", real, False),
        (
            "DEMOTING the critical scan back to run_advisory blocks",
            real.replace(
                'run_blocking_scan "pnpm audit (critical)"',
                'run_advisory "pnpm audit (critical)"',
            ),
            True,
        ),
        (
            "DELETING the critical scan blocks",
            "\n".join(ln for ln in real.splitlines() if CRITICAL_FLAG not in ln),
            True,
        ),
        (
            "a run_blocking_scan that does not set overall=1 blocks",
            real.replace(
                '            echo "x $name FAILED (exit $rc, ${_dur}s) — a finding at this severity BLOCKS."\n'
                "            overall=1\n",
                '            echo "x $name FAILED (exit $rc, ${_dur}s) — a finding at this severity BLOCKS."\n',
            ),
            True,
        ),
        (
            "a run_blocking_scan that treats a real finding as CANNOT-DETERMINE blocks",
            real.replace(
                '        if [[ "$rc" -eq "$AUDIT_CANNOT_DETERMINE" ]]; then',
                '        if [[ "$rc" -ge 1 ]]; then',
            ),
            True,
        ),
        (
            "an _audit_with_retry that launders a real finding into the sentinel blocks",
            real.replace(
                "        printf '%s\\n' \"$out\"          # a REAL finding — report it and fail immediately\n"
                "        return $rc",
                "        printf '%s\\n' \"$out\"          # a REAL finding — report it and fail immediately\n"
                '        return "$AUDIT_CANNOT_DETERMINE"',
            ),
            True,
        ),
        (
            "removing the sentinel declaration blocks",
            "\n".join(
                ln for ln in real.splitlines() if not ln.startswith(SENTINEL_DECL)
            ),
            True,
        ),
    ]

    rc = 0

    # Property 3 is driven directly: `check()` reads package.json and the lockfile from
    # disk rather than from `text`, so mutating the shell script cannot exercise it.
    def ok() -> str | None:
        return None

    def broken() -> str | None:
        return "the precondition this mute rests on is gone"

    ignore_cases: list[tuple[str, list[str], bool]] = [
        (
            "the real ignoreGhsas list passes",
            check_audit_ignores(),
            False,
        ),
        (
            "an UNJUSTIFIED mute blocks",
            check_audit_ignores(listed={"GHSA-0000-0000-0000"}, justifications={}),
            True,
        ),
        (
            "a justification for a mute that was REMOVED blocks",
            check_audit_ignores(listed=set(), justifications={"GHSA-x": ("why", ok)}),
            True,
        ),
        (
            "a mute whose PRECONDITION broke blocks",
            check_audit_ignores(
                listed={"GHSA-x"}, justifications={"GHSA-x": ("why", broken)}
            ),
            True,
        ),
        (
            "a mute whose precondition still holds passes",
            check_audit_ignores(
                listed={"GHSA-x"}, justifications={"GHSA-x": ("why", ok)}
            ),
            False,
        ),
    ]
    for label, failures, want_fail in ignore_cases:
        got_fail = bool(failures)
        good = got_fail == want_fail
        print(
            f"  {'✔' if good else '✗'} {label}: {'blocked' if got_fail else 'passed'}"
        )
        if not good:
            rc = 1
            for f in failures:
                print(f"      {f}")

    for label, text, want_fail in cases:
        # A mutation that did not change the file would make its case vacuous — the
        # anchor moved and the "proof" is proving nothing.
        if want_fail and text == real:
            print(f"  ✗ {label}: the mutation changed NOTHING — its anchor has moved")
            rc = 1
            continue
        failures = check(text)
        got_fail = bool(failures)
        ok = got_fail == want_fail
        print(f"  {'✔' if ok else '✗'} {label}: {'blocked' if got_fail else 'passed'}")
        if not ok:
            rc = 1
            for f in failures:
                print(f"      {f}")
    print("SELFTEST", "PASS" if rc == 0 else "FAIL")
    return rc


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--selftest":
        return selftest()
    if argv:
        print(f"unknown argument: {argv[0]}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    failures = check(VERIFY_ALL.read_text(encoding="utf-8"))
    if failures:
        print("gate runner semantics: FAIL")
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print(
        f"gate runner semantics: OK — {len(CASES) + 2} runner behaviours proven against "
        f"the real verify-all.sh bytes; {CRITICAL_FLAG} is wired to block; "
        f"{len(AUDIT_IGNORE_JUSTIFICATIONS)} audit mute(s) justified and their "
        f"preconditions still hold."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

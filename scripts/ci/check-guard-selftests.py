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
  check-guard-selftests.py               # every scripts/** guard invoked by verify-all.sh (cached — see CACHING)
  check-guard-selftests.py --no-cache    # ignore the cache, run every guard fresh (repopulates it)
  check-guard-selftests.py --changed-only # COMMIT STAGE ONLY - see below
  check-guard-selftests.py --selftest    # prove the meta-gate itself blocks
  check-guard-selftests.py --list        # show what it would check, run nothing
  check-guard-selftests.py --verbose     # print a line per guard (ok/cached/FAIL), not just the summary

CACHING — MEASURED 2026-09-02: this meta-gate was 451s of a 16-minute full gate,
every time, even when nothing guard-shaped had changed. A selftest's result is a
PURE FUNCTION of the guard script's own bytes plus a fixed tripwire set — CACHE_TRIPWIRES
below, which is CLAUDE.md §5's tripwire list plus this file's own bytes (a change to how
THIS script probes is itself a reason to distrust an old result). So the default (FULL)
mode keys each guard on sha256(guard bytes, tripwire bytes) and skips guards whose key
was already proven, writing `<cache_dir>/<guard-name>.<key>.ok` on a PASS only — a FAILED
selftest is never cached and is retried on every single run, same as today. The cache
lives OUTSIDE the repo at `${XDG_CACHE_HOME:-~/.cache}/tracelane/guard-selftests/`, never
committed, never shared by CI (a fresh runner has no cache and pays the full cost, which
is correct — CI is exactly the untrusted-until-proven context this gate exists for).
`--no-cache` bypasses cache READS (still writes fresh results) and is what the nightly
full gate should use once wired up — a scheduled backstop re-earns every proof rather than
trusting a key from hours ago; wiring that into `nightly-full-gate.yml` is a follow-up, not
done here. `--changed-only` is untouched by any of this — see below, still unchanged.

--changed-only IS A COMMIT-STAGE CONVENIENCE AND NOTHING ELSE.
A guard's selftest answers "does this guard still detect its violation?", and that
answer can only change when the guard, or something the guard READS, changes. So at
commit time we run the selftests for guards the diff touched and skip the rest.

It is NEVER passed by `.githooks/pre-push`. The push gate runs every selftest, every
time, with no diff-gating, because private-repo CI SKIPS its root jobs on a direct
push - `.githooks/pre-push` is the only enforcement a pushed commit ever sees. A
diff-gated push gate would mean a guard that rotted two commits ago is never
re-checked before the code leaves this machine.

WHAT COUNTS AS "TOUCHED" - a guard rots when its INPUTS change, not only its file.
`SHARED_GUARD_INPUTS` below lists the config guards read (allowlists, the
banned-phrase list, export deny rules, budgets). A change to ANY of them forces the
full run, because one line in `never-say-again.txt` changes what a dozen guards
assert while leaving every guard file untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
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

# Directories whose contents ARE guards. A change anywhere here re-runs everything:
# guards call each other and share helpers, so file-level attribution is not safe.
GUARD_DIRS = ("scripts/ci/", "scripts/hooks/", "scripts/export/")

# Config a guard READS. These are the rot source that file-level diffing misses
# entirely — none of them is a guard, and changing one silently changes what many
# guards assert. `never-say-again.txt` is the sharpest example: it lives OUTSIDE the
# three GUARD_DIRS above, and it is the banned-phrase list the honesty gates enforce.
SHARED_GUARD_INPUTS = (
    "scripts/never-say-again.txt",  # banned phrases (outside GUARD_DIRS - the point)
    "scripts/verify-all.sh",  # defines which guards run at all
    "deny.toml",  # cargo-deny bans
    "osv-scanner.toml",
    ".grype.yaml",
    ".gitleaks.toml",
)
# Any workflow file: several guards parse ci.yml (job graph, SHA pins, behavioral tier).
GUARD_INPUT_PREFIXES = (".github/workflows/",)


# ── Result cache (founder ruling 2026-09-02: 451s of a 16-min gate, every run,
# unconditionally, and "make sure we dont run those full gates if not needed"). ──
#
# A selftest's PASS/FAIL is a pure function of the guard script's own bytes plus a fixed
# set of inputs the gate itself depends on structurally — CLAUDE.md §5's tripwire list
# (verify-all.sh, the export/git-hook gates) plus this file's own bytes, because a change
# to how THIS script probes a guard is itself grounds to distrust a cached verdict. Key a
# guard on sha256 of exactly those bytes and a matching cache entry means "this exact
# selftest, against this exact tripwire state, already proved it blocks" — nothing more is
# being assumed. This is deliberately NOT `SHARED_GUARD_INPUTS` (that set governs
# --changed-only's file-level diff heuristic and is guard-CONFIG shaped — allowlists,
# banned-phrase lists); the cache tripwires are the narrower, provable set named in
# CLAUDE.md §5 itself, so the two lists are allowed to diverge without either being wrong.
CACHE_TRIPWIRES = (
    "scripts/verify-all.sh",
    "scripts/export/export-deny.txt",
    "scripts/export/build-public-export.sh",
    ".githooks/pre-commit",
    ".githooks/pre-push",
    "scripts/ci/check-guard-selftests.py",  # this file's own bytes
)


def _cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "tracelane" / "guard-selftests"


def _digest_file(p: Path) -> str:
    """sha256 hex of a file's bytes. A MISSING tripwire hashes as its own sentinel —
    not as empty — so deleting one invalidates every cache entry instead of quietly
    matching whatever else once hashed to the empty digest."""
    try:
        data = p.read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        data = b"<tracelane-cache-tripwire-absent>"
    return hashlib.sha256(data).hexdigest()


def _tripwire_digest(cwd: Path) -> str:
    """One digest over every CACHE_TRIPWIRES file, computed once per run and reused
    for every guard's key — the tripwire set is the same for all of them."""
    joined = ":".join(_digest_file(cwd / rel) for rel in CACHE_TRIPWIRES)
    return hashlib.sha256(joined.encode()).hexdigest()


def _cache_key(script: str, cwd: Path, tripwire_digest: str) -> str:
    """The whole idea in one function: a selftest result is a function of the guard's
    own bytes and the tripwire bytes, so THIS is that function, collapsed to a key."""
    joined = f"{_digest_file(cwd / script)}:{tripwire_digest}"
    return hashlib.sha256(joined.encode()).hexdigest()


def _cache_stem(script: str) -> str:
    """Filesystem-safe name for a guard: its repo-relative path, '/' -> '__', so two
    guards with the same basename in different dirs never collide on one cache file."""
    return script.replace("/", "__")


def _cache_ok_path(cache_dir: Path, script: str, key: str) -> Path:
    return cache_dir / f"{_cache_stem(script)}.{key}.ok"


def _cache_hit(cache_dir: Path, script: str, key: str) -> bool:
    return _cache_ok_path(cache_dir, script, key).is_file()


def _cache_write(cache_dir: Path, script: str, key: str) -> None:
    """Record a PASS. Only ever called after `--selftest` exits 0 — a failure must
    never reach here (see `check()`), so a red guard is retried every run."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    stem = _cache_stem(script)
    current = _cache_ok_path(cache_dir, script, key)
    # Drop stale entries for this guard under a DIFFERENT key first, or the cache
    # directory grows one file per edit to the guard or a tripwire, forever.
    for stale in cache_dir.glob(f"{stem}.*.ok"):
        if stale != current:
            stale.unlink(missing_ok=True)
    current.write_text(f"{datetime.now(timezone.utc).isoformat()}\n{key}\n")


def changed_files() -> list[str] | None:
    """Working tree + staged + untracked + unpushed, same shape verify-all.sh uses.

    Returns None when the diff cannot be bounded. None means CANNOT DETERMINE, and
    every caller treats that as "run everything" — never as "nothing changed".
    """

    def _git(*a: str) -> list[str]:
        r = subprocess.run(
            ["git", *a], cwd=ROOT, capture_output=True, text=True, check=False
        )
        return r.stdout.split("\n") if r.returncode == 0 else []

    if (
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        ).returncode
        != 0
    ):
        return None
    files = set()
    files.update(_git("diff", "--name-only", "HEAD"))
    files.update(_git("diff", "--name-only", "--cached"))
    files.update(_git("ls-files", "--others", "--exclude-standard"))
    up = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if up.returncode == 0 and up.stdout.strip():
        files.update(_git("diff", "--name-only", f"{up.stdout.strip()}...HEAD"))
    return sorted(f for f in files if f)


def full_run_reason(files: list[str] | None) -> str | None:
    """Why the whole set must run, or None if selective is safe."""
    if files is None:
        return "the diff could not be bounded (CANNOT DETERMINE, so: everything)"
    for f in files:
        if f in SHARED_GUARD_INPUTS:
            return f"a shared guard INPUT changed: {f}"
        if f.startswith(GUARD_INPUT_PREFIXES):
            return f"a workflow guards parse changed: {f}"
        # A NON-script file inside a guard directory is CONFIG a guard reads —
        # export-deny.txt, bench-budgets.json, migration-drift-acknowledged.txt,
        # STAGING_FILELIST.baseline.txt. None of them is a guard, and changing one
        # changes what several guards assert while leaving every guard file
        # untouched. That is precisely the rot file-level diffing misses, so it
        # forces the full run rather than selecting a guard by name.
        if f.startswith(GUARD_DIRS) and not f.endswith((".py", ".sh")):
            return f"guard CONFIG changed: {f}"
    return None


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


# ── Per-script probe budgets. ────────────────────────────────────────────────
#
# 300 s fits every guard that greps the tree. It does NOT fit a guard whose
# falsification COMPILES RUST: `run-postgres-integration.sh --selftest` reverts a
# cast in an isolated worktree with its own `CARGO_TARGET_DIR` (deliberately not
# shared — a falsification that contaminates the thing it falsifies proves
# nothing) and rebuilds the test binary there.
#
# MEASURED 2026-08-24, not guessed: 116 s standalone on an idle box. Under the
# gate's own parallel load it crossed 300 s on three consecutive runs and was
# reported as "1 of 83 guard(s) cannot prove they block" — a RED that said the
# guard was broken when the guard was fine and the clock was short. A control
# that goes red for a reason unrelated to the property it checks is a control
# people learn to re-run rather than read.
SLOW_SELFTESTS: dict[str, int] = {
    "scripts/ci/run-postgres-integration.sh": 900,
    # B-285: same shape as its Postgres sibling — this one spins a ClickHouse container
    # AND rebuilds the gateway test binary, then runs the whole suite a second time to
    # prove it goes red. At 300s it timed out on 2026-08-25, and because the selftest
    # MUTATES A TRACKED SOURCE the kill left the tree carrying B-272's exact defect and
    # failed an unrelated step. A short clock on a mutating guard is not a slow test, it
    # is a corrupted worktree.
    "scripts/ci/run-clickhouse-integration.sh": 900,
    # B-383 (c): starts the prod ClickHouse image twice (the proof, then the planted
    # over-grant) and waits for the schema each time — ~90 s clean, more under load.
    "scripts/ci/check-clickhouse-users.sh": 600,
    # B-383 (b): starts nats-server and runs two ignored cargo tests (a rebuild of both
    # test binaries when the tree moved) — ~60 s warm, minutes cold.
    "scripts/ci/check-nats-auth.sh": 900,
}


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


def check(
    verify_all: Path = VERIFY_ALL,
    cwd: Path = ROOT,
    only: set[str] | None = None,
    verbose: bool = False,
    use_cache: bool = False,
    cache_dir: Path | None = None,
) -> tuple[int, list[str], int, int]:
    """`only` limits the SELFTEST probes to those scripts; existence is always checked.

    Existence is never skipped: it costs a stat, and "verify-all.sh invokes a guard
    that does not exist" is a defect in verify-all.sh, not in the guard, so no diff
    of guard files can be trusted to reveal it.

    `use_cache` is FULL-MODE ONLY (`only is None`, callers do not pass both) — see the
    module docstring's CACHING section. It is never True for a `--changed-only` run:
    that path already narrows by diff, and CLAUDE.md §5 requires the push-stage FULL
    run stay un-diff-gated, which the cache satisfies a different way (a guard whose
    bytes or tripwires did not move is genuinely unchanged, not merely un-diffed).

    Returns (guard count, failures, ran, cached) — `ran` counts guards whose
    `--selftest` subprocess actually executed this call; `cached` counts guards
    skipped on a cache hit. Both are 0 whenever `use_cache` is False.
    """
    failures: list[str] = []
    ran = 0
    cached = 0
    guards = invoked_guards(verify_all)
    tripwire_digest = _tripwire_digest(cwd) if use_cache else ""
    resolved_cache_dir = (cache_dir or _cache_dir()) if use_cache else None
    for script, prefix in guards:
        if not (cwd / script).exists():
            failures.append(f"{script}: invoked by verify-all.sh but does not exist")
            if verbose:
                print(f"  MISSING  {script}")
            continue
        if only is not None and script not in only:
            if verbose:
                print(f"  skipped  {script} (untouched by this diff)")
            continue

        key = None
        if use_cache:
            assert resolved_cache_dir is not None
            key = _cache_key(script, cwd, tripwire_digest)
            if _cache_hit(resolved_cache_dir, script, key):
                cached += 1
                if verbose:
                    print(f"  cached   {script}")
                continue

        run = runner_for(script, prefix)

        # Probe 1 — argv must be parsed. This is what makes probe 2 evidence.
        rc_bogus = probe([*run, script, BOGUS], cwd)
        if rc_bogus == 0:
            failures.append(
                f"{script}: exits 0 for `{BOGUS}` — it does not parse argv, so a "
                "`--selftest` pass would prove NOTHING"
            )
            if verbose:
                print(f"  FAIL     {script}  (accepts any flag)")
            continue

        if script in UNSELFTESTABLE:
            continue  # rejects unknown flags; selftest waived with a recorded reason

        # Probe 2 — the selftest must actually pass.
        budget = SLOW_SELFTESTS.get(script, 300)
        rc_self = probe([*run, script, "--selftest"], cwd, timeout=budget)
        ran += 1
        if rc_self != 0:
            # A TIMEOUT AND A REFUSAL ARE DIFFERENT FACTS, and collapsing them is
            # how a slow box reads as a broken guard. `124` is this module's own
            # sentinel for "the probe ran out of time", not an exit code the
            # script chose — so it is named as such. A FAILED selftest is NEVER
            # cached (below) — this is what makes that true.
            why = (
                f"the probe TIMED OUT after {budget}s (the guard did not report "
                "anything — this is a clock, not a verdict)"
                if rc_self == 124
                else f"`--selftest` exited {rc_self} (expected 0)"
            )
            failures.append(f"{script}: {why}")
            if verbose:
                print(f"  FAIL     {script}  ({why})")
        else:
            if verbose:
                print(f"  ok       {script}")
            if use_cache:
                assert resolved_cache_dir is not None and key is not None
                _cache_write(resolved_cache_dir, script, key)
    return len(guards), failures, ran, cached


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

        n, f, _ran, _cached = check(va('    run "good" python3 scripts/ci/good.py'), td)
        assert n == 1 and not f, f"selftest: a well-behaved guard must PASS, got {f}"
        print("✓ selftest: a guard with a real selftest passes")

        n, f, _ran, _cached = check(va('    run "liar" bash scripts/ci/liar.sh'), td)
        assert len(f) == 1 and "does not parse argv" in f[0], f"got {f}"
        print(
            "✓ selftest: a guard that accepts ANY flag is caught (the 20-script shape)"
        )

        n, f, _ran, _cached = check(
            va('    run "broken" python3 scripts/ci/broken.py'), td
        )
        assert len(f) == 1 and "exited 1" in f[0], f"got {f}"
        print("✓ selftest: a guard whose selftest FAILS is caught")

        n, f, _ran, _cached = check(va('    run "gone" python3 scripts/ci/gone.py'), td)
        assert len(f) == 1 and "does not exist" in f[0], f"got {f}"
        print("✓ selftest: a guard invoked but missing is caught")

        # The parser must not silently drop guards — if it did, everything "passes".
        n, f, _ran, _cached = check(
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

    # ── The cache: proven in its own isolated tree, own isolated cache dir. Never
    # touches the real ~/.cache — every check() call above passes use_cache=False
    # (the default), and every call below points cache_dir at a temp directory. ──
    with tempfile.TemporaryDirectory() as td2:
        td2 = Path(td2)
        (td2 / "scripts" / "ci").mkdir(parents=True)
        cache_dir2 = td2 / "cache"

        # A real repo carries these tripwires; give the fixture the same shape so
        # `_tripwire_digest` reads real bytes rather than the absent-file sentinel
        # for all six on every call (which would still be CORRECT, just a weaker
        # proof — an always-absent tripwire can never demonstrate invalidation).
        for rel in CACHE_TRIPWIRES:
            p = td2 / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists():
                p.write_text("tripwire fixture\n")

        def va2(*lines: str) -> Path:
            p = td2 / "verify-all.sh"
            p.write_text("\n".join(lines) + "\n")
            return p

        cacheable = td2 / "scripts" / "ci" / "cacheable.py"
        cacheable.write_text(
            "import sys\n"
            "if '--selftest' in sys.argv: print('ok'); sys.exit(0)\n"
            "if len(sys.argv) > 1: sys.exit(2)\n"
            "sys.exit(0)\n"
        )
        verify_all2 = va2('    run "cacheable" python3 scripts/ci/cacheable.py')

        # (1) a guard selftested once is CACHED on the second call.
        n, f, ran, cached = check(
            verify_all2, td2, use_cache=True, cache_dir=cache_dir2
        )
        assert n == 1 and not f and ran == 1 and cached == 0, (
            f"first run must actually RUN the selftest: n={n} f={f} ran={ran} cached={cached}"
        )
        n, f, ran, cached = check(
            verify_all2, td2, use_cache=True, cache_dir=cache_dir2
        )
        assert n == 1 and not f and ran == 0 and cached == 1, (
            f"second run must be CACHED, not re-run: ran={ran} cached={cached}"
        )
        print("✓ selftest: a guard selftested once is cached on the second call")

        # (2) ONE byte of the guard script changes -> the cache entry is invalidated.
        cacheable.write_text(cacheable.read_text() + "# one more byte\n")
        n, f, ran, cached = check(
            verify_all2, td2, use_cache=True, cache_dir=cache_dir2
        )
        assert n == 1 and not f and ran == 1 and cached == 0, (
            f"a changed guard script must MISS the cache: ran={ran} cached={cached}"
        )
        print(
            "✓ selftest: one changed byte in the guard script invalidates its cache entry"
        )

        # (2b) the same holds for a tripwire byte, not just the guard's own — the key
        # is guard bytes AND tripwires, and this is the half a same-guard-only test
        # cannot exercise.
        tripwire_fixture = td2 / CACHE_TRIPWIRES[0]
        tripwire_fixture.write_text(tripwire_fixture.read_text() + "# changed\n")
        n, f, ran, cached = check(
            verify_all2, td2, use_cache=True, cache_dir=cache_dir2
        )
        assert ran == 1 and cached == 0, (
            f"a changed tripwire must invalidate every guard's cache entry: "
            f"ran={ran} cached={cached}"
        )
        print("✓ selftest: a changed tripwire file invalidates the cache too")

        # (3) a FAILING selftest is never cached — it must be retried every run.
        failing = td2 / "scripts" / "ci" / "failing.py"
        failing.write_text(
            "import sys\n"
            "if '--selftest' in sys.argv: sys.exit(1)\n"
            "if len(sys.argv) > 1: sys.exit(2)\n"
            "sys.exit(0)\n"
        )
        verify_all3 = va2('    run "failing" python3 scripts/ci/failing.py')
        n, f, ran, cached = check(
            verify_all3, td2, use_cache=True, cache_dir=cache_dir2
        )
        assert n == 1 and len(f) == 1 and ran == 1 and cached == 0, (
            f"a failing selftest must not be cached on its first run: f={f} ran={ran} cached={cached}"
        )
        n, f, ran, cached = check(
            verify_all3, td2, use_cache=True, cache_dir=cache_dir2
        )
        assert n == 1 and len(f) == 1 and ran == 1 and cached == 0, (
            "a FAILING selftest must NEVER be cached — it has to be re-attempted "
            f"every run, got f={f} ran={ran} cached={cached}"
        )
        print(
            "✓ selftest: a failing selftest is never cached, and is re-run every time"
        )

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--selftest", action="store_true", help="prove the meta-gate blocks"
    )
    ap.add_argument("--list", action="store_true", help="list what would be checked")
    ap.add_argument(
        "--changed-only",
        action="store_true",
        help="COMMIT STAGE ONLY: selftest just the guards this diff touches. "
        "Never pass this on push — see the module docstring.",
    )
    ap.add_argument(
        "--why-full",
        action="store_true",
        help=(
            "print WHY a --changed-only run would refuse to narrow (and exit 0), "
            "or print nothing and exit 1 if it would narrow. Runs NO guards. "
            "R129: verify-all.sh calls this up front so the 441s cost is announced "
            "at the TOP of the run instead of being discoverable only from one line "
            "buried in a 102-step log."
        ),
    )
    ap.add_argument(
        "--no-cache",
        action="store_true",
        help=(
            "ignore the on-disk selftest cache (see CACHING in the module docstring) "
            "and run every guard's --selftest fresh, repopulating the cache as it "
            "goes. Has no effect combined with --changed-only, which never uses the "
            "cache anyway. Intended for a scheduled/nightly full gate, which should "
            "re-earn every proof rather than trust a key from hours ago — wiring "
            "this into nightly-full-gate.yml is a follow-up, not done by this flag."
        ),
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="print a line per guard (ok/cached/skipped/MISSING/FAIL), not just "
        "the one-line summary",
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.list:
        for s, p in invoked_guards(VERIFY_ALL):
            print(f"  {' '.join(runner_for(s, p))} {s}")
        return 0

    only: set[str] | None = None
    if args.why_full:
        reason = full_run_reason(changed_files())
        if reason:
            print(reason)
            return 0
        return 1

    if args.changed_only:
        files = changed_files()
        reason = full_run_reason(files)
        if reason is None:
            assert files is not None
            only = {
                f
                for f in files
                if f.startswith(GUARD_DIRS) and f.endswith((".py", ".sh"))
            }
            print(
                f"--changed-only: {len(only)} guard file(s) in the diff; "
                "selftesting those, existence-checking all."
            )
            print(
                "  NOTE: this is the COMMIT stage. `.githooks/pre-push` runs every "
                "selftest with no diff-gating."
            )
        else:
            print(f"--changed-only requested but running EVERYTHING: {reason}")

    # The cache is FULL-MODE ONLY (§ module docstring CACHING) — never with
    # --changed-only, which already narrows by diff and must stay exactly as it was.
    use_cache = not args.changed_only and not args.no_cache
    n, failures, ran, cached = check(
        only=only, verbose=args.verbose, use_cache=use_cache
    )
    for f in failures:
        print(f"FAIL {f}")

    if only is not None:
        print(
            f"guard selftests: {len(only)} of {n} selftested (commit stage), "
            f"{n} existence-checked. Push runs all {n}."
        )
    else:
        print(
            f"meta-gate: {ran} ran, {cached} cached "
            "(key = guard bytes + tripwires), "
            f"{len(failures)} failed"
        )

    if failures:
        print(
            f"\n{len(failures)} of {n} guard(s) invoked by verify-all.sh cannot prove they "
            "block.\nA guard whose falsification has never been observed is not a guard — "
            "it is a\nscript that has only ever been seen agreeing with the repo."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

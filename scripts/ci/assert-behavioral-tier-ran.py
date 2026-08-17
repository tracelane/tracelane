#!/usr/bin/env python3
"""assert-behavioral-tier-ran — did the behavioural net actually get cast?

WHY THIS EXISTS, AND WHY IT WAS REWRITTEN (B-169, 2026-08-11)
============================================================
The `behavioral-tier-ran` job asserts that the four behavioural-tier jobs EXECUTED
(as opposed to being silently `skipped` by a path gate). It already carried
`if: always()`, which is the usual fix for "a skipped need skips the dependant".

**That was not enough, and the run that proved it was run `31511826456`.** The job
sat `in_progress` while the run concluded `failure` — so on the one run where the
question mattered, **it asserted nothing at all**.

The cause is the `needs:` edge itself, not the `if:`. `always()` means "run even if
a need FAILED"; it does not mean "run even if a need never REACHES A CONCLUSION".
A job that hangs, gets cancelled, or never gets a runner leaves every dependant
waiting forever. So the guard could only speak once all four upstream jobs had
finished — **precisely the situation in which you do not need it.** A guard that is
only reachable when nothing is wrong is decoration.

THE INVERSION
=============
Stop *depending* on the tier jobs and start *observing* them. This reads the run's
own job list from the Actions API and polls until each target job reaches a terminal
state (or a timeout expires). It therefore runs to completion and produces a verdict
no matter what the tier jobs do — including hanging forever, which is the case the
`needs:` version could not survive.

WHAT COUNTS AS "RAN"
====================
  * `success`   -> ran
  * `failure`   -> RAN. The run is already red from that job; failing here too
                   would blur which of two problems this is. This job answers
                   "was the net cast", never "did it catch anything".
  * `skipped` / `cancelled` -> did NOT run. This is the defect.
  * never terminal before the timeout -> did NOT run, and is reported as such
    rather than as an absence. That is the exact case that produced this rewrite.

HONEST LIMIT
============
It proves the jobs executed. It cannot prove they asserted anything useful — a
behavioural job that runs and tests nothing still reports `success` here. It also
depends on the Actions API being reachable; an API failure is reported as
CANNOT DETERMINE and exits non-zero rather than passing by default, because a guard
that fails open is the thing this file exists to stop.

EXIT: 0 all target jobs executed · 1 one or more did not · 2 usage / cannot determine
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

# The behavioural net. Names must match the `name:` of each job in ci.yml — the
# API reports display names, not job ids.
#
# THIS IS A SECOND LIST, and it drifted the day it was first tested (2026-08-13).
# Renaming the release-guard job in ci.yml to say what it now covers made this
# tuple stop matching, and the guard reported "1 of 4 behavioral jobs DID NOT
# EXECUTE" — a TRUE alarm with a FALSE diagnosis. The job ran; the name moved.
# `assert_targets_exist_in_ci_yml` below makes that distinction explicit, because
# "renamed" and "did not run" call for opposite responses and a guard that
# conflates them sends you looking in the wrong place.
TARGETS = (
    "Live eval gate (real stack —  meta-fix / L2)",
    "L16 Playwright dead-button gate (§12)",
    "Span publish → JetStream ( regression)",
    "Release-profile tenant guard (ingest + shared)",
)

CI_YML = (
    pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
)


def assert_targets_exist_in_ci_yml() -> None:
    """Every TARGET must still be a `name:` in ci.yml.

    Fail-fast with the RIGHT diagnosis. Without this, a renamed job is reported
    as one that did not execute — which is true of the name and false of the
    world, and sends the reader hunting a skipped job that actually ran.
    """
    try:
        src = CI_YML.read_text(encoding="utf-8")
    except OSError as e:
        # Cannot see is not "fine" (CLAUDE.md 1.14).
        print(f"FATAL: cannot read {CI_YML}: {e}", file=sys.stderr)
        raise SystemExit(2) from e
    missing = [t for t in TARGETS if f"name: {t}" not in src]
    if missing:
        print(
            "FATAL: these TARGETS are not job names in ci.yml any more — they were\n"
            "RENAMED, not skipped. Update TARGETS to match ci.yml:",
            file=sys.stderr,
        )
        for m in missing:
            print(f"  * {m!r}", file=sys.stderr)
        raise SystemExit(2)


TERMINAL = {
    "success",
    "failure",
    "skipped",
    "cancelled",
    "timed_out",
    "action_required",
}
RAN = {"success", "failure", "timed_out"}

POLL_SECONDS = 15
DEFAULT_TIMEOUT_SECONDS = 240


def verdict(jobs: list[dict], targets: tuple[str, ...]) -> list[tuple[str, str, bool]]:
    """Pure: [(job_name, state, ran)]. Testable without the network.

    A target the API never mentions is reported as `absent` and counts as NOT ran —
    "I cannot see it" is not "it is fine" (CLAUDE.md §1.14).
    """
    by_name = {j.get("name", ""): j for j in jobs}
    out: list[tuple[str, str, bool]] = []
    for name in targets:
        job = by_name.get(name)
        if job is None:
            out.append((name, "absent", False))
            continue
        status = job.get("status") or ""
        conclusion = job.get("conclusion")
        if status != "completed" or conclusion is None:
            # Non-terminal. THE case that produced this rewrite.
            out.append((name, f"{status or 'unknown'} (never concluded)", False))
            continue
        out.append((name, conclusion, conclusion in RAN))
    return out


def all_terminal(jobs: list[dict], targets: tuple[str, ...]) -> bool:
    by_name = {j.get("name", ""): j for j in jobs}
    for name in targets:
        job = by_name.get(name)
        if job is None:
            return False
        if job.get("status") != "completed" or job.get("conclusion") not in TERMINAL:
            return False
    return True


def fetch_jobs(repo: str, run_id: str, token: str) -> list[dict]:
    """Every job in this run. Paginated — a run with >100 jobs must not be
    silently truncated into a false 'absent'."""
    jobs: list[dict] = []
    page = 1
    while True:
        url = (
            f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
            f"?per_page=100&page={page}"
        )
        # Fixed https host, no user-supplied scheme.
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "tracelane-ci",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        batch = payload.get("jobs", [])
        jobs.extend(batch)
        if len(batch) < 100:
            return jobs
        page += 1


def selftest() -> int:
    """Prove the verdict BLOCKS on each way a job can fail to execute."""
    fails = 0
    t = ("A", "B")

    def case(label: str, jobs: list[dict], want_ran: list[bool]) -> None:
        nonlocal fails
        got = [ran for _, _, ran in verdict(jobs, t)]
        if got == want_ran:
            print(f"  ✓ {label}")
        else:
            print(f"  ✗ {label} — wanted {want_ran}, got {got}")
            fails += 1

    def done(n: str, c: str) -> dict:
        return {"name": n, "status": "completed", "conclusion": c}

    case(
        "both success -> ran",
        [done("A", "success"), done("B", "success")],
        [True, True],
    )
    # A job that RAN and FAILED still executed — this guard is not a second
    # failure signal for the same problem.
    case(
        "failure still counts as RAN",
        [done("A", "failure"), done("B", "success")],
        [True, True],
    )
    case(
        "skipped is NOT ran",
        [done("A", "skipped"), done("B", "success")],
        [False, True],
    )
    case(
        "cancelled is NOT ran",
        [done("A", "cancelled"), done("B", "success")],
        [False, True],
    )
    # THE case that produced this rewrite: a job that never concluded. The
    # `needs:`-based version could not even reach this assertion.
    case(
        "in_progress / never concluded is NOT ran",
        [
            {"name": "A", "status": "in_progress", "conclusion": None},
            done("B", "success"),
        ],
        [False, True],
    )
    # A target the API never mentions must not pass by omission.
    case("a job absent from the API is NOT ran", [done("B", "success")], [False, True])

    # all_terminal must refuse to stop polling while anything is unfinished,
    # or the timeout is decorative.
    if not all_terminal(
        [{"name": "A", "status": "in_progress", "conclusion": None}], ("A",)
    ):
        print("  ✓ polling does not stop while a job is unfinished")
    else:
        print("  ✗ would stop polling on an unfinished job")
        fails += 1
    if all_terminal([done("A", "skipped")], ("A",)):
        print(
            "  ✓ polling stops once every job is terminal (skipped counts as terminal)"
        )
    else:
        print("  ✗ would poll forever on a terminal-but-skipped job")
        fails += 1

    if fails:
        print(f"behavioral-tier-ran selftest FAILED — {fails} case(s).")
        return 1
    print("behavioral-tier-ran selftest PASSED.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        if argv[1] == "--selftest":
            return selftest()
        print(f"assert-behavioral-tier-ran: unknown option: {argv[1]}", file=sys.stderr)
        return 2

    # BEFORE any network call: prove the TARGETS still name real jobs. A rename
    # and a skip produce the same "did not execute" reading otherwise, and they
    # call for opposite fixes.
    assert_targets_exist_in_ci_yml()

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    # TIER_RUN_ID, not GITHUB_RUN_ID. **GitHub silently ignores any `env:` that
    # tries to override a `GITHUB_*` variable**, so the workflow's attempt to point
    # this at the TRIGGERING run was dropped and the script inspected the observer's
    # OWN run — whose job list contains only this one job, so all four targets read
    # `absent`. Caught on observer run 31530539758. It failed CLOSED, which is the
    # design working, but the cause was a reserved-name collision: the self-match
    # trap in workflow form, and my mitigation for it did not take.
    run_id = os.environ.get("TIER_RUN_ID") or os.environ.get("GITHUB_RUN_ID", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    timeout_s = int(os.environ.get("TIER_ASSERT_TIMEOUT", DEFAULT_TIMEOUT_SECONDS))
    if not (repo and run_id and token):
        print(
            "CANNOT DETERMINE — GITHUB_REPOSITORY / GITHUB_RUN_ID / GITHUB_TOKEN unset."
        )
        print(
            "Refusing to pass by default: a guard that fails OPEN is what this replaces."
        )
        return 2

    deadline = time.monotonic() + timeout_s
    jobs: list[dict] = []
    while True:
        try:
            jobs = fetch_jobs(repo, run_id, token)
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"CANNOT DETERMINE — Actions API unreachable: {e}")
            return 2
        if all_terminal(jobs, TARGETS) or time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)

    rows = verdict(jobs, TARGETS)
    missing = [(n, s) for n, s, ran in rows if not ran]

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = [
        "### Behavioral tier — did it actually run?",
        "",
        "Observed from the run's own job list (not via `needs:`), so this reports a",
        "verdict even when an upstream job hangs or never concludes.",
        "",
        "| job | state | executed? |",
        "|---|---|---|",
    ]
    for name, state, ran in rows:
        lines.append(f"| `{name}` | {state} | {'✅' if ran else '❌'} |")
    text = "\n".join(lines)
    print(text)
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")

    if missing:
        print()
        print(f"❌ {len(missing)} of {len(TARGETS)} behavioral jobs DID NOT EXECUTE:")
        for name, state in missing:
            print(f"     {name} -> {state}")
        print()
        print("  A behavioural job that did not run is not a pass. On schedule /")
        print("  workflow_dispatch the `changes` job fail-safes to run-all, so")
        print("  `skipped` here is unambiguously wrong.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

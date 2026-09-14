#!/usr/bin/env python3
"""Fail on a GitHub-hosted CI job that can fire without founder approval.

WHY (founder, 2026-09-07). GitHub-hosted Actions runners (`ubuntu-*`, `windows-*`,
`macos-*`) are billed on this account; the self-hosted `tl-node-1` box (reached via
`${{ vars.CI_RUNNER || 'ubuntu-latest' }}`) is free. The founder's ruling, verbatim:
"ensure to only use in extreme case with my approval" — after FOUR hosted Benchmarks
runs fired today alone (measured: `gh api .../actions/runs`, one of them 55 minutes).
`ci.yml`'s three hardcoded-hosted jobs (`api-key-mint-postgres`, `live-eval-gate`,
`bench`) now require `workflow_dispatch` with `inputs.hosted_runners ==
'approved-by-founder'`, and this is the executable gate that keeps a future hosted
job — or a regression in one of these three — from shipping without the same opt-in.
CLAUDE.md §12: a rule becomes an executable gate or it is context debt.

WHAT IT CHECKS. For every job in every `.github/workflows/*.yml` whose `runs-on`
resolves to a GitHub-hosted label (a literal `ubuntu-*`/`windows-*`/`macos-*`, or a
`${{ matrix.<field> }}` reference whose matrix values include one) — with the single
exception of the `${{ vars.CI_RUNNER || 'ubuntu-latest' }}` indirection, which is
ALREADY the approved self-hosted-first pattern used by every other job in this repo —
the job's own `if:` must satisfy ONE of:

  (a) it contains `inputs.hosted_runners == 'approved-by-founder'` (the opt-in), AND,
      if the workflow ALSO has a `schedule:` trigger, the `if:` excludes schedule by
      checking `github.event_name == 'workflow_dispatch'` (or `!= 'schedule'`) — an
      opt-in with no schedule-exclusion still fires, unattended and billed, on the
      cron that motivated this guard in the first place; or

  (b) it contains `github.repository == 'tracelane/tracelane'` — the PUBLIC-repo
      guard. This is a STRONGER protection than the opt-in (it blocks every private
      trigger unconditionally, not merely non-approved ones), which is why it exempts
      BOTH the opt-in and the schedule-exclusion checks. It is not limited to
      `release*.yml`: `codeql.yml`, `security-scan.yml` (5 jobs), `sbom.yml` and
      `scorecard.yml` all already carry exactly this condition, predating this guard,
      and a filename-scoped exemption would have flagged all eight as violations the
      day this guard shipped — for jobs that, per `gh api .../actions/runs`, have
      concluded `skipped` on every single private firing (zero billable minutes)
      since before this guard existed. Scoping the exemption to the condition itself,
      not the filename it happens to appear in, is what makes that true.

USAGE
  check-hosted-runner-optin.py                    # every workflow in .github/workflows
  check-hosted-runner-optin.py <dir-or-file>...    # explicit paths (selftest uses this)
  check-hosted-runner-optin.py --selftest          # prove it blocks AND passes

HONEST LIMIT — read before trusting a pass. This parses structurally (indentation +
regex), the same way `check-workflow-job-graph.py` and `check-action-sha-pins.py` do —
deliberately not PyYAML, for the same reason `check-export-references.py` gives:
this runs on whatever python3 is present, and a guard that cannot run because a
dependency is missing is the failure mode the file exists to prevent. It resolves a
`${{ matrix.<field> }}` reference by scanning the nearest `matrix:` block for that
job for ANY hosted-looking label anywhere in it, not by binding the exact field —
good enough for every workflow in this tree today, but a matrix keyed on an unrelated
field name that happens to also list a hosted OS elsewhere in the same block could
false-positive. It reads the job's OWN `if:` only; it does not trace `needs:` chains,
so a job that inherits protection PURELY from a skipped upstream dependency (GitHub's
default skip-cascade) is invisible to it — every hosted job in this repo's release*
workflows was given its OWN explicit `if:` for exactly this reason (see their
comments). A green result means "every hosted job's own `if:` carries one of the two
protections", never "this workflow cannot possibly bill" — `runs-on: ${{ steps.… }}`
or another runtime-computed value this guard cannot see would pass silently.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = ROOT / ".github" / "workflows"

RE_TOP = re.compile(r"^\S")
RE_JOB = re.compile(r"^  ([A-Za-z0-9_.-]+):\s*(#.*)?$")

# A hosted label GitHub reserves: ubuntu-latest, ubuntu-24.04, windows-2022,
# macos-14, etc. Bounded on both sides so "tl-node-1" or a custom label containing
# "ubuntu" as a substring (none do today) is not accidentally matched.
HOSTED_LABEL_RE = re.compile(
    r"(?<![\w-])(ubuntu|windows|macos)-[A-Za-z0-9._]+", re.IGNORECASE
)

# The approved self-hosted-first indirection. Any job using it is safe REGARDLESS of
# what the fallback resolves to — see the module docstring.
CI_RUNNER_RE = re.compile(r"vars\.CI_RUNNER")

OPT_IN_RE = re.compile(r"""inputs\.hosted_runners\s*==\s*['"]approved-by-founder['"]""")
RELEASE_GUARD_RE = re.compile(
    r"""github\.repository\s*==\s*['"]tracelane/tracelane['"]"""
)
SCHEDULE_EXCLUDE_RE = re.compile(
    r"""github\.event_name\s*==\s*['"]workflow_dispatch['"]|github\.event_name\s*!=\s*['"]schedule['"]"""
)

BLOCK_SCALARS = {"", ">", ">-", ">+", "|", "|-", "|+"}


# ── Parsing ──────────────────────────────────────────────────────────────────────
def collect_jobs(lines: list[str]) -> dict[str, list[tuple[int, str]]]:
    """job name -> [(1-based lineno, raw line)] for every line belonging to that job
    (everything indented under its 2-space header), same style as
    check-workflow-job-graph.py's job/needs parser."""
    jobs: dict[str, list[tuple[int, str]]] = {}
    in_jobs = False
    current: str | None = None
    for i, line in enumerate(lines, 1):
        if RE_TOP.match(line):
            in_jobs = line.startswith("jobs:")
            current = None
            continue
        if not in_jobs:
            continue
        m = RE_JOB.match(line)
        if m:
            name = m.group(1)
            jobs[name] = []
            current = name
            continue
        if current is not None:
            jobs[current].append((i, line))
    return jobs


def has_schedule_trigger(lines: list[str]) -> bool:
    on_idx = None
    inline = ""
    for i, line in enumerate(lines):
        m = re.match(r"^on:\s*(.*)$", line)
        if m:
            on_idx = i
            inline = m.group(1).strip()
            break
    if on_idx is None:
        return False
    if inline and "schedule" in inline:
        return True
    for line in lines[on_idx + 1 :]:
        if line.strip() == "":
            continue
        if not line[0].isspace():
            break
        if re.match(r"^\s*schedule:\s*(#.*)?$", line):
            return True
    return False


def _get_value(job_lines: list[tuple[int, str]], key: str) -> tuple[str, int] | None:
    """First `<key>: <value>` at 4-space indent within a job. A block scalar
    (`>-`, `|`, empty) collects subsequent more-indented lines into one string."""
    pattern = re.compile(rf"^    {re.escape(key)}:\s*(.*)$")
    for idx, (lineno, line) in enumerate(job_lines):
        m = pattern.match(line)
        if not m:
            continue
        val = m.group(1).strip()
        if val in BLOCK_SCALARS:
            parts: list[str] = []
            for _, t in job_lines[idx + 1 :]:
                if t.strip() == "":
                    continue
                indent = len(t) - len(t.lstrip(" "))
                if indent <= 4:
                    break
                parts.append(t.strip())
            return " ".join(parts), lineno
        # Strip a trailing comment, but only when unquoted — several `if:` values
        # here legitimately contain a `#` only inside a quoted string... none do
        # today, but this is the same caution check-action-sha-pins.py's sibling
        # guards take: don't risk truncating a real expression to save a case.
        if '"' not in val and "'" not in val:
            val = val.split(" #", 1)[0].strip()
        return val, lineno
    return None


def _matrix_block_text(job_lines: list[tuple[int, str]]) -> str:
    """Text of the nearest `matrix:` block in this job, however deep it is nested
    (under `strategy:`) — used only to resolve a `${{ matrix.<field> }}` runs-on."""
    text = "\n".join(t for _, t in job_lines)
    m = re.search(r"^(\s*)matrix:\s*$", text, re.MULTILINE)
    if not m:
        return ""
    indent = len(m.group(1))
    rest = text[m.end() :].split("\n")
    collected: list[str] = []
    for line in rest:
        if line.strip() == "":
            continue
        ind = len(line) - len(line.lstrip(" "))
        if ind <= indent:
            break
        collected.append(line)
    return "\n".join(collected)


def _is_hosted(runs_on: str, job_lines: list[tuple[int, str]]) -> bool:
    if CI_RUNNER_RE.search(runs_on):
        return False  # the approved indirection — safe regardless of fallback
    if HOSTED_LABEL_RE.search(runs_on):
        return True
    if "matrix." in runs_on:
        # Best-effort: any hosted-looking label anywhere in the job's matrix block.
        # See the module docstring's HONEST LIMIT.
        return bool(HOSTED_LABEL_RE.search(_matrix_block_text(job_lines)))
    return False


# ── Check ────────────────────────────────────────────────────────────────────────
def check_file(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").split("\n")
    rel = path.relative_to(ROOT) if ROOT in path.parents else path
    scheduled = has_schedule_trigger(lines)
    findings: list[str] = []

    for job, job_lines in collect_jobs(lines).items():
        runs_on = _get_value(job_lines, "runs-on")
        if runs_on is None:
            continue  # no runs-on (e.g. a reusable-workflow `uses:` job) — out of scope
        runs_on_val, runs_on_line = runs_on
        if not _is_hosted(runs_on_val, job_lines):
            continue

        if_val, if_line = _get_value(job_lines, "if") or ("", runs_on_line)

        if RELEASE_GUARD_RE.search(if_val):
            continue  # stronger-than-opt-in protection — see module docstring

        if not OPT_IN_RE.search(if_val):
            findings.append(
                f"{rel}:{runs_on_line}: job `{job}` runs on a GitHub-hosted label "
                f"({runs_on_val.strip()!r}) but its `if:` does not require "
                f"inputs.hosted_runners == 'approved-by-founder' (line {if_line})"
            )
            continue  # don't double-report the same job for the schedule check too

        if scheduled and not SCHEDULE_EXCLUDE_RE.search(if_val):
            findings.append(
                f"{rel}:{if_line}: job `{job}` is GitHub-hosted and opted in, but this "
                "workflow has a `schedule:` trigger and the `if:` does not exclude it "
                "(no `github.event_name == 'workflow_dispatch'` / `!= 'schedule'`) — "
                "it will still fire, unattended and billed, on the cron"
            )

    return findings


def check(paths: list[Path]) -> int:
    files: list[Path] = []
    for p in paths:
        files.extend(
            sorted(p.glob("*.yml")) + sorted(p.glob("*.yaml")) if p.is_dir() else [p]
        )

    bad = 0
    for f in files:
        for line in check_file(f):
            print(f"FAIL {line}")
            bad += 1

    if bad:
        print(
            f"\n{bad} hosted-runner job(s) that can fire without founder approval. "
            "Hosted GitHub Actions runners are billed on this account and the founder's "
            "ruling (2026-09-07) is explicit: only in an extreme case, with approval.\n"
            "Fix: add `github.event_name == 'workflow_dispatch' && inputs.hosted_runners "
            "== 'approved-by-founder'` to the job's `if:` (and add the matching "
            "`workflow_dispatch.inputs.hosted_runners` choice input if the workflow "
            "doesn't have one yet), OR — if this job must never run privately at all — "
            "`github.repository == 'tracelane/tracelane'`, which is the stronger "
            "guarantee and exempts both checks."
        )
        return 1
    print(f"hosted-runner opt-in: clean ({len(files)} file(s))")
    return 0


# ── Selftest ─────────────────────────────────────────────────────────────────────
def selftest() -> int:
    import tempfile

    def w(td: Path, name: str, body: str) -> Path:
        p = td / name
        p.write_text(body)
        return p

    with tempfile.TemporaryDirectory() as tdname:
        td = Path(tdname)

        # (a) a hosted job with NO opt-in at all — must BLOCK.
        no_optin = w(
            td,
            "no_optin.yml",
            "name: t\non:\n  push: {}\njobs:\n  x:\n    runs-on: ubuntu-latest\n"
            "    steps: []\n",
        )
        assert check([no_optin]) == 1, (
            "selftest: a hosted job with no opt-in must BLOCK"
        )
        print("✓ selftest: a hosted job without the opt-in BLOCKS")

        # (b) a scheduled hosted job: opt-in present, but the workflow has `schedule:`
        # and the `if:` never checks event_name — it would still fire on the cron.
        # This is the exact shape the ci.yml `bench` job carried before 2026-09-07.
        scheduled_hosted = w(
            td,
            "scheduled_hosted.yml",
            "name: t\non:\n  schedule:\n    - cron: '0 3 * * 0'\n"
            "  workflow_dispatch:\n    inputs:\n      hosted_runners:\n"
            "        type: choice\n        options: ['no', 'approved-by-founder']\n"
            "        default: 'no'\n"
            "jobs:\n  x:\n    runs-on: ubuntu-latest\n"
            "    if: inputs.hosted_runners == 'approved-by-founder'\n"
            "    steps: []\n",
        )
        assert check([scheduled_hosted]) == 1, (
            "selftest: a scheduled hosted job must BLOCK"
        )
        print(
            "✓ selftest: an opted-in hosted job that does not exclude `schedule:` BLOCKS"
        )

        # (c) a clean opted-in job — must PASS. Includes the schedule trigger too, to
        # prove the event_name check is what satisfies BOTH requirements at once.
        clean_optin = w(
            td,
            "clean_optin.yml",
            "name: t\non:\n  schedule:\n    - cron: '0 3 * * 0'\n"
            "  workflow_dispatch:\n    inputs:\n      hosted_runners:\n"
            "        type: choice\n        options: ['no', 'approved-by-founder']\n"
            "        default: 'no'\n"
            "jobs:\n  x:\n    runs-on: ubuntu-latest\n"
            "    if: >-\n"
            "      github.event_name == 'workflow_dispatch'\n"
            "      && inputs.hosted_runners == 'approved-by-founder'\n"
            "    steps: []\n",
        )
        assert check([clean_optin]) == 0, "selftest: a clean opted-in job must PASS"
        print("✓ selftest: a clean opted-in job (with a schedule trigger) PASSES")

        # (d) a clean CI_RUNNER job — the approved indirection, no `if:` at all — PASS.
        clean_ci_runner = w(
            td,
            "clean_ci_runner.yml",
            "name: t\non:\n  schedule:\n    - cron: '0 3 * * 0'\n  push: {}\n"
            "jobs:\n  x:\n    runs-on: \"${{ vars.CI_RUNNER || 'ubuntu-latest' }}\"\n"
            "    steps: []\n",
        )
        assert check([clean_ci_runner]) == 0, (
            "selftest: a clean CI_RUNNER job must PASS"
        )
        print("✓ selftest: a clean CI_RUNNER job (no `if:` needed) PASSES")

        # (e) the repository-guard exemption — NOT filename-scoped. This is what lets
        # codeql.yml / security-scan.yml / sbom.yml / scorecard.yml (none named
        # release*.yml) pass without the opt-in, because they already carry a
        # STRONGER protection. Also proves it exempts the schedule check.
        repo_guard = w(
            td,
            "not_a_release_file.yml",
            "name: t\non:\n  schedule:\n    - cron: '0 3 * * 0'\n  push: {}\n"
            "jobs:\n  x:\n    runs-on: ubuntu-latest\n"
            "    if: github.repository == 'tracelane/tracelane'\n    steps: []\n",
        )
        assert check([repo_guard]) == 0, (
            "selftest: a job with the repository guard must PASS regardless of filename"
        )
        print("✓ selftest: the repository guard exempts a hosted job (any filename)")

        # A self-hosted custom label (no hosted substring) must never be flagged.
        self_hosted = w(
            td,
            "self_hosted.yml",
            "name: t\non: [push]\njobs:\n  x:\n    runs-on: [self-hosted, tl-node-1]\n"
            "    steps: []\n",
        )
        assert check([self_hosted]) == 0, "selftest: a self-hosted label must PASS"
        print("✓ selftest: a bare self-hosted label PASSES")

        # A `uses:` reusable-workflow-call job has no `runs-on:` at all — out of scope,
        # must not crash and must not be flagged.
        reusable_call = w(
            td,
            "reusable.yml",
            "name: t\non: [push]\njobs:\n  x:\n    needs: y\n"
            "    uses: org/repo/.github/workflows/w.yml@abc\n",
        )
        assert check([reusable_call]) == 0, (
            "selftest: a reusable-workflow call must PASS"
        )
        print(
            "✓ selftest: a `uses:`-only job (no `runs-on:`) is out of scope and PASSES"
        )

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="hosted-runner founder-opt-in gate")
    ap.add_argument("paths", nargs="*", help="workflow files or directories")
    ap.add_argument(
        "--selftest", action="store_true", help="prove the gate blocks and passes"
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    paths = [Path(a).resolve() for a in args.paths] or [DEFAULT_DIR]
    for p in paths:
        if not p.exists():
            print(f"FAIL: {p} does not exist")
            return 1
    return check(paths)


if __name__ == "__main__":
    sys.exit(main())

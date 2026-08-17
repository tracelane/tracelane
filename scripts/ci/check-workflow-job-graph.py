#!/usr/bin/env python3
"""Fail on a GitHub Actions workflow whose `needs:` names a job that does not exist.

WHY (2026-08-09). The PUBLIC repo's CI produced **zero jobs and conclusion=failure on
every run from 2026-08-04 to 2026-08-09** — five days with no executing CI anywhere,
because the private side skips all 14 jobs on push (`ci.yml:126,:559,:729`) and the
public run that was supposed to compensate was an INVALID WORKFLOW.

The mechanism: `scripts/export/build-public-export.sh` drops job blocks that cannot run
publicly, on an assumption written at its `:109` — *"Every remaining job only `needs:
changes`, so dropping these dangles no `needs:` reference."* That was true when written.
B-169 then added `behavioral-tier-ran`, which `needs:` FOUR of the dropped jobs. The
exported YAML declared needs on jobs that no longer existed, GitHub refused the whole
file, and the failure looked identical to a normal red run — no job ever started, so
there was no failing step to read.

This is the `green-workflow-is-not-green-surface` shape inverted: a RED run that nobody
could diagnose because the redness was structural, not a test result.

A comment cannot hold that invariant — only a check that reads the emitted file can.
Run it on BOTH sides: the private tree (so a new job is caught at author time) and the
exported tree (so the transform's own output is proven self-consistent before it ships).

USAGE
  check-workflow-job-graph.py                    # every workflow in .github/workflows
  check-workflow-job-graph.py <dir-or-file>...   # e.g. the staged public export
  check-workflow-job-graph.py --selftest         # prove a dangling need BLOCKS

HONEST LIMIT — read before trusting a pass. This parses structurally, the same way
`build-public-export.sh` itself does (a job header is a 2-space-indented `<name>:`), so
the guard and the transform agree by construction. It checks ONE property: every name in
a `needs:` resolves to a declared job in the same file. It does NOT validate the rest of
the workflow schema — a bad `runs-on`, a malformed `if:` or an unknown `uses:` all pass
here. A green result means "the job graph is closed", not "GitHub will accept this file".
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = ROOT / ".github" / "workflows"

# A job header, exactly as build-public-export.sh:122 recognises one.
RE_JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
RE_TOP = re.compile(r"^\S")
RE_NEEDS_INLINE = re.compile(r"^\s{4}needs:\s*(.+?)\s*$")
RE_NEEDS_BLOCK = re.compile(r"^\s{4}needs:\s*$")


def parse(path: Path) -> tuple[set[str], list[tuple[str, str, int]]]:
    """Return (declared job names, [(job, needed_name, lineno), ...])."""
    lines = path.read_text(encoding="utf-8").split("\n")

    # Only the `jobs:` mapping declares jobs. A 2-space key under `on:` (e.g. `push:`)
    # is not a job, and counting it would let a real dangling need hide behind it.
    in_jobs = False
    jobs: set[str] = set()
    needs: list[tuple[str, str, int]] = []
    current = ""
    collecting = False

    for i, line in enumerate(lines, 1):
        if RE_TOP.match(line):
            in_jobs = line.startswith("jobs:")
            collecting = False
            continue
        if not in_jobs:
            continue

        m = RE_JOB.match(line)
        if m:
            current = m.group(1)
            jobs.add(current)
            collecting = False
            continue

        if RE_NEEDS_BLOCK.match(line):
            collecting = True
            continue

        m = RE_NEEDS_INLINE.match(line)
        if m:
            for n in _names(m.group(1)):
                needs.append((current, n, i))
            # A flow sequence may span lines: `needs:\n  [a,\n b]` is handled by the
            # block collector below when the bracket has not closed.
            collecting = "[" in m.group(1) and "]" not in m.group(1)
            continue

        if collecting:
            # Block sequence (`- name`) or the continuation of a flow sequence.
            if re.match(r"^\s{4}\S", line) and not re.match(
                r"^\s+[-\[\]]", line.rstrip()
            ):
                collecting = False
                continue
            for n in _names(line):
                needs.append((current, n, i))
            if "]" in line:
                collecting = False

    return jobs, needs


def _names(chunk: str) -> list[str]:
    chunk = chunk.split("#", 1)[0]
    chunk = (
        chunk.strip().strip("[]").replace("-", " ", 1)
        if chunk.strip().startswith("-")
        else chunk.strip().strip("[]")
    )
    return [
        t
        for t in (p.strip().strip("'\"") for p in chunk.split(","))
        if t and t.isidentifier() or (t and re.fullmatch(r"[A-Za-z0-9_-]+", t))
    ]


def check(paths: list[Path]) -> int:
    files: list[Path] = []
    for p in paths:
        files.extend(
            sorted(p.glob("*.yml")) + sorted(p.glob("*.yaml")) if p.is_dir() else [p]
        )

    bad = 0
    for f in files:
        jobs, needs = parse(f)
        for job, needed, lineno in needs:
            if needed not in jobs:
                rel = f.relative_to(ROOT) if ROOT in f.parents else f
                print(
                    f"FAIL {rel}:{lineno}: job `{job}` needs `{needed}`, "
                    f"which is not declared in this file"
                )
                bad += 1
    if bad:
        print(
            f"\n{bad} dangling `needs:` reference(s). GitHub rejects the ENTIRE workflow "
            "for this,\nso every job reports skipped/failed with no step to diagnose — the "
            "shape that hid\nfive days of dead public CI (2026-08-04 → 08-09).\n"
            "If a job was dropped by build-public-export.sh, drop its dependants too."
        )
        return 1
    print(f"workflow job graph: clean ({len(files)} file(s))")
    return 0


def selftest() -> int:
    import tempfile

    good = """\
name: t
on: [push]
jobs:
  changes:
    runs-on: ubuntu-latest
  build:
    needs: changes
    runs-on: ubuntu-latest
  gate:
    needs: [changes, build]
    runs-on: ubuntu-latest
  wide:
    needs:
      [
        changes,
        build,
      ]
    runs-on: ubuntu-latest
"""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        ok = td / "ok.yml"
        ok.write_text(good)
        assert check([ok]) == 0, "selftest: a closed job graph must PASS"
        print("✓ selftest: closed graph passes (inline, flow and multi-line needs)")

        bad = td / "bad.yml"
        bad.write_text(
            good.replace(
                "  build:\n    needs: changes\n    runs-on: ubuntu-latest\n", ""
            )
        )
        assert check([bad]) == 1, "selftest: a dangling `needs:` must BLOCK"
        print("✓ selftest: dropped job leaves a dangling need and BLOCKS")

        # An `on:` trigger key must not be mistaken for a declared job — otherwise a
        # need on `push` would resolve and a real dangling reference could hide.
        trap = td / "trap.yml"
        trap.write_text(
            "name: t\non:\n  push:\n    branches: [main]\njobs:\n  a:\n    needs: push\n    runs-on: x\n"
        )
        assert check([trap]) == 1, "selftest: an `on:` key must not count as a job"
        print("✓ selftest: an `on:` trigger key does not satisfy a `needs:`")

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--selftest"]
    if "--selftest" in sys.argv:
        return selftest()
    paths = [Path(a).resolve() for a in args] or [DEFAULT_DIR]
    for p in paths:
        if not p.exists():
            print(f"FAIL: {p} does not exist")
            return 1
    return check(paths)


if __name__ == "__main__":
    sys.exit(main())

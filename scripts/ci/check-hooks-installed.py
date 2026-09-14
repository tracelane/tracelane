#!/usr/bin/env python3
"""The git hooks are the ONLY enforcement on a direct push — so refuse to gate a clone that has not installed them.

WHY THIS EXISTS (B-384, 2026-09-12). The independent review's harness finding: enforcement
here is local and opt-in. Private CI skips its substantive jobs on `push` by policy
(`.github/workflows/ci.yml`, the `changes` job — a measured cost decision), branch
protection is a GitHub plan away, and `.githooks/pre-push` runs `verify-all.sh` ONLY when
`git config core.hooksPath .githooks` has been run in that clone. A fresh clone runs no
hook at all: a `git push` from it reaches `main` with nothing having been checked, and
nothing says so.

Two halves close the free part of that:

  1. `package.json` `prepare` runs `git config core.hooksPath .githooks` on every
     `pnpm install`, so the hooks install themselves on the first thing a fresh clone
     does anyway.
  2. THIS check, in preflight and in the full gate: if the clone running the gate has
     no `core.hooksPath` pointing at `.githooks`, the gate FAILS with the one-line fix.
     A green local gate in a clone that will then push unhooked is a green that
     protects nothing.

The other half — running substantive CI on private pushes — is not free: the
self-hosted runner IS the prod box (B-382), and every push-time job lands on it. That
half waits on the second box (the founder tracker, internal).

Skipped, with a line saying so, when `CI` / `GITHUB_ACTIONS` is set: a CI checkout never
commits or pushes, so hooks there are meaningless.

USAGE
  check-hooks-installed.py            # exit 0 = hooks installed (or CI), 1 = not
  check-hooks-installed.py --selftest # prove the verdict logic BLOCKS an unhooked clone
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WANTED = ".githooks"


def verdict(hooks_path: str | None, in_ci: bool) -> tuple[bool, str]:
    """Pure decision: (ok, message)."""
    if in_ci:
        return True, "git hooks: SKIP — CI checkout, nothing here commits or pushes"
    normalized = (hooks_path or "").strip().rstrip("/")
    # Accept the relative form git stores and an absolute path INTO this repo.
    if normalized == WANTED or normalized.endswith("/" + WANTED):
        return True, f"git hooks: OK — core.hooksPath = {normalized}"
    if not normalized:
        return False, (
            "git hooks: NOT INSTALLED — `core.hooksPath` is unset in this clone, so "
            "`.githooks/pre-commit` and `.githooks/pre-push` never run and a `git push` "
            "from here is ungated. Fix: git config core.hooksPath .githooks "
            "(`pnpm install` does this for you)."
        )
    return False, (
        f"git hooks: WRONG PATH — core.hooksPath = {normalized!r}, expected {WANTED!r}. "
        "Fix: git config core.hooksPath .githooks"
    )


def current_hooks_path() -> str | None:
    try:
        out = subprocess.run(
            ["git", "config", "--get", "core.hooksPath"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def selftest() -> int:
    cases = [
        ("installed (relative)", ".githooks", False, True),
        ("installed (absolute into repo)", str(ROOT / ".githooks"), False, True),
        ("unset BLOCKS", None, False, False),
        ("empty BLOCKS", "   ", False, False),
        ("some other path BLOCKS", ".git/hooks", False, False),
        ("CI checkout is skipped even when unset", None, True, True),
    ]
    rc = 0
    for label, path, ci, want_ok in cases:
        ok, _ = verdict(path, ci)
        good = ok == want_ok
        print(f"  {'✔' if good else '✗'} {label}: {'ok' if ok else 'blocked'}")
        if not good:
            rc = 1
    print("SELFTEST", "PASS" if rc == 0 else "FAIL")
    return rc


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--selftest":
        return selftest()
    if argv:
        print(f"unknown argument: {argv[0]}", file=sys.stderr)
        return 2
    in_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    ok, msg = verdict(current_hooks_path(), in_ci)
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

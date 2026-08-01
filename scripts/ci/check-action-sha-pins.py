#!/usr/bin/env python3
"""Fail if any workflow `uses:` names an action without a 40-hex commit SHA.

Why this exists
---------------
`CLAUDE.md` requires "All GitHub Actions SHA-pinned, never tag-pinned", and
`CLAUDE_CODE_STARTUP_AUDIT.md` §3.3 lists a grep for it. Until now that grep was
run **by hand** — the rule was documented, audited manually, and enforced by
nobody. A tag is mutable: `uses: foo/bar@v3` resolves to whatever the tag points
at today, so an upstream compromise or a retagged release executes in our CI with
the workflow token in scope.

This is the enforcement the docs already assumed existed. It also becomes the
gate for Dependabot auto-merge of action bumps (B-163): auto-merging is only safe
if something mechanically refuses a bump that drops the pin.

Scope: every `.github/workflows/*.yml`. Exempt:
  - local actions (`uses: ./path`) — no registry, nothing to pin
  - docker refs (`uses: docker://…@sha256:…`) — pinned by digest instead

Exit codes: 0 clean, 1 violation(s) found.

Selftest: `--selftest` plants a tag-pinned `uses:` and asserts it is reported, so
the guard is never trusted on the basis of having passed.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# `uses: owner/repo[/path]@ref` — capture the whole ref.
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^'\"\s#]+)['\"]?", re.MULTILINE)
SHA_RE = re.compile(r"@[0-9a-f]{40}$")


def workflows() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", ".github/workflows/*.yml", ".github/workflows/*.yaml"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [ROOT / p for p in out.stdout.split("\n") if p.strip()]


def scan(path: Path) -> list[tuple[int, str]]:
    """Return [(lineno, ref)] for every `uses:` lacking a 40-hex SHA."""
    bad: list[tuple[int, str]] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
        m = USES_RE.match(line)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith("./"):  # local action
            continue
        if ref.startswith("docker://") and "@sha256:" in ref:
            continue
        if not SHA_RE.search(ref):
            bad.append((i, ref))
    return bad


def run(files: list[Path]) -> int:
    violations = 0
    for f in files:
        for lineno, ref in scan(f):
            print(
                f"{f.relative_to(ROOT)}:{lineno}: `uses: {ref}` is not SHA-pinned",
                file=sys.stderr,
            )
            violations += 1
    if violations:
        print(
            f"\n{violations} tag-pinned action(s). A tag is mutable — an upstream\n"
            "retag or compromise runs in CI with the workflow token in scope.\n"
            "Pin to the 40-hex commit SHA, keeping the version as a comment:\n"
            "  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2\n"
            "Resolve with:\n"
            "  gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object.sha\n"
            "(if that returns type=tag, deref: gh api repos/<o>/<r>/git/tags/<sha> --jq .object.sha)",
            file=sys.stderr,
        )
        return 1
    print(f"action SHA pins: clean ({len(files)} workflow file(s))")
    return 0


def selftest() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        good = tmp / "good.yml"
        good.write_text(
            "jobs:\n  a:\n    steps:\n"
            "      - uses: actions/checkout@" + "a" * 40 + "  # v4.2.2\n"
            "      - uses: ./.github/actions/local\n"
            "      - uses: docker://alpine@sha256:" + "b" * 64 + "\n",
            encoding="utf-8",
        )
        if scan(good):
            print("✗ selftest: a fully-pinned file was reported", file=sys.stderr)
            return 1

        bad = tmp / "bad.yml"
        bad.write_text(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
            encoding="utf-8",
        )
        hits = scan(bad)
        if not hits:
            print(
                "✗ selftest: a TAG-pinned action was not reported — guard is decorative",
                file=sys.stderr,
            )
            return 1
        print(f"✓ selftest: tag pin detected at line {hits[0][0]} ({hits[0][1]})")

        short = tmp / "short.yml"
        short.write_text(
            "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + "a" * 7 + "\n",
            encoding="utf-8",
        )
        if not scan(short):
            print(
                "✗ selftest: a SHORT sha was accepted — must require the full 40 hex",
                file=sys.stderr,
            )
            return 1
        print("✓ selftest: short sha rejected; local + docker-digest refs exempt")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    files = workflows()
    if not files:
        print(
            "✗ no workflow files found — the guard would pass vacuously",
            file=sys.stderr,
        )
        return 1
    return run(files)


if __name__ == "__main__":
    raise SystemExit(main())

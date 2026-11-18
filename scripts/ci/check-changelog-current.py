#!/usr/bin/env python3
"""Fail when the public changelog lags the newest deploy by more than GRACE_DAYS.

The /changelog page (apps/site/src/data/changelog-data.ts) stopped at 2026-09-26
while the whole gateway program deployed after it; nothing noticed for four weeks.
Truth for "something shipped" is the ROADMAP status cell: a row whose status says
DEPLOYED (not NOT-DEPLOYED) carries the date in that cell — AND every feat/fix commit
on the branch that changes product code without saying `Changelog: none — <reason>`.
The second source exists because bug fixes never flip a ROADMAP row: six
customer-visible fixes (10-23 → 10-30) sat off the page while this check said OK.
Not every deploy needs an entry, hence the grace window rather than a per-row match.

Exit 0 current, 1 stale, 2 could not read either source. `--selftest` proves both.
"""

from __future__ import annotations

import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROADMAP = ROOT / "docs/runbook/ROADMAP.md"
CHANGELOG = ROOT / "apps/site/src/data/changelog-data.ts"
GRACE_DAYS = 7

DATE = re.compile(r"\b(20\d\d-\d\d-\d\d)\b")


def newest_deploy(roadmap: str) -> date | None:
    best = None
    for line in roadmap.splitlines():
        cells = line.split("|")
        if len(cells) < 4 or not cells[1].strip().startswith("`"):
            continue
        status = cells[2]
        if "DEPLOYED" not in status.replace("NOT-DEPLOYED", "").replace(
            "NOT DEPLOYED", ""
        ):
            continue
        for d in DATE.findall(status):
            dd = date.fromisoformat(d)
            best = dd if best is None or dd > best else best
    return best


def newest_entry(changelog: str) -> date | None:
    ds = [
        date.fromisoformat(d)
        for d in re.findall(r'date:\s*"(20\d\d-\d\d-\d\d)"', changelog)
    ]
    return max(ds) if ds else None


PRODUCT_PATHS = ("crates/gateway/", "crates/ingest/", "apps/web/", "packages/")
NOT_PRODUCT = re.compile(
    r"(^|/)(tests?|e2e)/|_tests?\.rs$|(^|/)tests\.rs$|\.(test|spec)\.tsx?$|\.md$|Cargo\.toml$"
)
PRODUCT_SUBJECT = re.compile(r"^(feat|fix)(\(|!?:)")
NONE_NOTE = re.compile(r"^Changelog: none\b", re.IGNORECASE | re.MULTILINE)


def is_product_path(path: str) -> bool:
    """Shipped product code — tests, docs and manifests are not something a customer sees.
    Shared with check-commit-governance.py so the two checks cannot drift."""
    return path.startswith(PRODUCT_PATHS) and not NOT_PRODUCT.search(path)


def owed_commits(log: str, after: date) -> list[tuple[date, str]]:
    """`log` is `git log --format=%x01%cd%x00%B%x02 --date=short --name-only` (no
    pathspec — the file list must still show the changelog): feat/fix commits that
    change product code, dated after the newest entry, that neither add an entry nor
    say `Changelog: none — …`. Dates are committer dates, the ones `--since` filters."""
    out = []
    changelog = str(CHANGELOG.relative_to(ROOT))
    for rec in log.split("\x01")[1:]:
        day, _, rest = rec.partition("\x00")
        body, _, files = rest.partition("\x02")
        try:
            d = date.fromisoformat(day.strip())
        except ValueError:
            continue
        paths = files.split("\n")
        subject = body.strip().splitlines()[0] if body.strip() else ""
        if (
            d <= after
            or not PRODUCT_SUBJECT.match(subject)
            or NONE_NOTE.search(body)
            or changelog in paths
            or not any(is_product_path(f.strip()) for f in paths)
        ):
            continue
        out.append((d, subject))
    return out


def git_log(after: date) -> str:
    return subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "log",
            f"--since={after.isoformat()}",
            "--format=%x01%cd%x00%B%x02",
            "--date=short",
            "--name-only",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def verdict(
    roadmap: str, changelog: str, commits: list[tuple[date, str]] = ()
) -> tuple[int, str]:
    dep, ent = newest_deploy(roadmap), newest_entry(changelog)
    if dep is None or ent is None:
        return (
            2,
            f"CANNOT DETERMINE — newest deploy {dep}, newest changelog entry {ent}",
        )
    if commits:
        dep = max(dep, max(d for d, _ in commits))
    lag = (dep - ent).days
    if lag > GRACE_DAYS:
        return 1, (
            f"FAIL — public changelog is {lag} days behind: newest entry {ent}, newest "
            f"DEPLOYED row {dep}. Add entries to {CHANGELOG.relative_to(ROOT)} "
            "(customer wording: what you can now do)."
            + "".join(f"\n  owed: {d} {subj}" for d, subj in commits)
        )
    return 0, f"OK — changelog newest {ent}, newest deploy {dep} (grace {GRACE_DAYS} d)"


def selftest() -> int:
    rm = "| `X-1` | **DEPLOYED 2026-10-20** (web `abc`) | t |\n| `X-2` | **BUILT-NOT-DEPLOYED** (2026-12-01) | t |\n"
    log = (
        "\x012026-10-30\x00fix(gateway): budgets count embeddings\n\nbody\n\x02\ncrates/gateway/src/a.rs\n"
        "\x012026-10-30\x00feat(gateway): flag-off slice\n\nChangelog: none — flag off\n\x02\ncrates/gateway/src/b.rs\n"
        "\x012026-10-30\x00fix(gateway): ships its own entry\n\x02\ncrates/gateway/src/d.rs\napps/site/src/data/changelog-data.ts\n"
        "\x012026-10-30\x00fix(gateway): tests only\n\x02\ncrates/gateway/src/action_control/export_pg_tests.rs\n"
        "\x012026-10-30\x00fix(gateway): no file list\n\nChangelog: none — merge\n\x02\n"
        "\x012026-10-18\x00fix(web): before the entry\n\x02\napps/web/lib/c.ts\n"
    )
    cases = [
        ("stale changelog FAILS", verdict(rm, 'date: "2026-09-26"')[0] == 1),
        ("current changelog PASSES", verdict(rm, 'date: "2026-10-19"')[0] == 0),
        (
            "a NOT-DEPLOYED row's date is ignored",
            newest_deploy(rm) == date(2026, 10, 20),
        ),
        ("unreadable sources are CANNOT DETERMINE", verdict("", "")[0] == 2),
        (
            "an uncovered product fix FAILS with no ROADMAP flip",
            verdict(rm, 'date: "2026-10-19"', owed_commits(log, date(2026, 10, 19)))[0]
            == 1,
        ),
        (
            "only the uncovered product fix is owed (none-note, own entry, tests-only, no files, older)",
            [s for _, s in owed_commits(log, date(2026, 10, 19))]
            == ["fix(gateway): budgets count embeddings"],
        ),
    ]
    for name, ok in cases:
        print(("  ✓ " if ok else "  ✗ ") + name)
    ok = all(ok for _, ok in cases)
    print("selftest OK" if ok else "selftest FAILED")
    return 0 if ok else 1


def main() -> int:
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    try:
        roadmap = ROADMAP.read_text(encoding="utf-8")
        changelog = CHANGELOG.read_text(encoding="utf-8")
        ent = newest_entry(changelog)
        commits = owed_commits(git_log(ent), ent) if ent else []
        rc, msg = verdict(roadmap, changelog, commits)
    except (OSError, subprocess.CalledProcessError) as e:
        rc, msg = 2, f"CANNOT DETERMINE — {e}"
    print(msg, file=sys.stderr if rc else sys.stdout)
    return rc


if __name__ == "__main__":
    sys.exit(main())

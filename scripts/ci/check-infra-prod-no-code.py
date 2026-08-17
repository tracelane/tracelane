#!/usr/bin/env python3
"""`infra/prod/**` is excluded from CI path-filtering — so it must contain NO built code.

WHY (2026-08-09, founder-ruled with conditions). A one-file change to
`infra/prod/clickhouse/config.xml` ran Rust, Web, evals AND a cold release-mode benchmark:
~16 billable minutes to benchmark code that had not changed. `ci.yml`'s `changes` filter
treats `infra/*` as cross-cutting and fail-safes to run-all — correct as a default
(uncertainty must WIDEN the gate), but against a 2,000-minute allowance already carrying
~400 min/mo of re-enabled `guards`, a release benchmark against a ClickHouse XML file is
noise. Noise is how a red run stops being read.

So `infra/prod/*` now short-circuits the filter. THIS GUARD IS THE CONDITION ON THAT: the
exclusion is only safe while nothing under `infra/prod/` is compiled, bundled or tested by
any CI job. The moment a `.rs`, `.ts`, `.tsx` or `.py` lands there, the exclusion becomes a
hole — code that ships with NO Rust/Web/Python job ever seeing it. That failure would be
invisible; this makes it loud.

TWO DELIBERATE NARROWINGS, both load-bearing:

  * **`infra/prod` ONLY, never `infra/*`.** `infra/dev` and `infra/self-host` feed real
    test stacks (`live-eval-stack.sh` composes `infra/dev/docker-compose.yml`), so they
    stay cross-cutting.
  * **`.sql` is NOT in the banned set, because it is still cross-cutting in `ci.yml`.**
    `infra/prod/*.sql` is matched BEFORE the ops-only skip, so a schema change there still
    triggers run-all. `infra/prod/partition-cutover.sql` is the one instance today.
    Banning `.sql` here instead would have made this guard RED FROM BIRTH, and a
    never-green gate reads as background noise (`never-green-has-no-green-to-lose`).

HONEST LIMIT. This proves no BUILT-LANGUAGE source file sits under `infra/prod/`. It does
not prove the excluded files are harmless — a wrong Caddyfile or systemd unit can break
production just as thoroughly, and no CI job here checks those either (before or after this
change). What changed is the billing, not the coverage: those files were never compiled or
tested, they merely triggered a benchmark of unrelated code.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUARDED_PREFIX = "infra/prod/"

# Extensions that a CI job compiles, bundles or tests. `.sql` is deliberately absent —
# see the module docstring.
BANNED_SUFFIXES = (".rs", ".ts", ".tsx", ".py")


def tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "infra/prod"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return [p for p in out.split("\n") if p]


def offenders(paths: list[str]) -> list[str]:
    return sorted(
        p for p in paths if p.startswith(GUARDED_PREFIX) and p.endswith(BANNED_SUFFIXES)
    )


def selftest() -> int:
    clean = [
        "infra/prod/clickhouse/config.xml",
        "infra/prod/docker-compose.yml",
        "infra/prod/blue-green-deploy.sh",
        "infra/prod/partition-cutover.sql",
        "infra/prod/ops/tlane-watchdog.service",
    ]
    assert not offenders(clean), (
        f"selftest: an ops-only tree must PASS, got {offenders(clean)}"
    )
    print("✓ selftest: xml/yml/sh/service/sql under infra/prod pass")

    for bad, label in [
        ("infra/prod/helper.rs", "Rust"),
        ("infra/prod/scripts/deploy.ts", "TypeScript"),
        ("infra/prod/ui/Panel.tsx", "TSX"),
        ("infra/prod/tools/migrate.py", "Python"),
    ]:
        got = offenders([*clean, bad])
        assert got == [bad], f"selftest: {label} under infra/prod must BLOCK, got {got}"
        print(f"✓ selftest: a {label} file under infra/prod BLOCKS the exclusion")

    # The guard must be SCOPED — the same file elsewhere is none of its business,
    # otherwise it would fire on the entire repo.
    assert not offenders(["crates/gateway/src/server.rs", "apps/web/app/page.tsx"]), (
        "selftest: files outside infra/prod must be ignored"
    )
    print("✓ selftest: code OUTSIDE infra/prod is ignored (scoped, not repo-wide)")

    # `.sql` must NOT be banned — banning it would make the guard red from birth.
    assert not offenders(["infra/prod/partition-cutover.sql"]), (
        "selftest: .sql is cross-cutting in ci.yml and must not be banned here"
    )
    print("✓ selftest: .sql is NOT banned (still cross-cutting in ci.yml)")

    assert not offenders([]), "empty input must not fabricate findings"
    print("✓ selftest: empty input yields zero findings (no false coverage)")

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="infra/prod CI-exclusion safety gate")
    ap.add_argument("--selftest", action="store_true", help="prove the gate blocks")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    files = tracked_files()
    bad = offenders(files)
    for b in bad:
        print(f"FAIL {b}: built-language source under infra/prod/")
    if bad:
        print(
            "\n`infra/prod/**` is EXCLUDED from ci.yml's path filter, so nothing here is\n"
            "compiled, bundled or tested by any job. A source file placed here would ship\n"
            "with NO Rust/Web/Python job ever seeing it.\n\n"
            "Move it under crates/ · apps/ · packages/ · scripts/, or remove the\n"
            "`infra/prod/*) continue;;` case from ci.yml's `changes` job and accept the\n"
            "~16 billable minutes per ops commit."
        )
        return 1
    print(
        f"infra/prod CI exclusion: safe ({len(files)} tracked file(s), no built-language source)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

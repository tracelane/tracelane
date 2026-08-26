#!/usr/bin/env python3
"""No browser session-state dump may be TRACKED. Filename rule, on purpose.

WHY THIS EXISTS — 2026-08-19, and it is a real incident rather than a precaution.

`apps/web/C:UsersSanjeevtl-auth-state.json` was committed on 2026-08-17 and
reached the PUBLIC mirror. It is a Playwright `storageState` dump: eight cookies
for `.tracelane.dev` and the WorkOS AuthKit domain, including the `wos-auth-*`
session verifiers.

Three things had to line up, and all three are worth naming because each one is
still true for the next such file:

  1. **The filename was a mangled Windows path.** `TL_AUTH_STATE` held a
     `C:\\Users\\...` value and the Linux run treated the whole string as one
     filename, so the dump landed in `apps/web/` instead of wherever the author
     believed. Nothing looked wrong in the test output.
  2. **`apps/web` is an ALLOWLISTED export tree** (CLAUDE.md §4a). A new file
     under an allowlisted parent ships publicly BY DEFAULT — that section says so
     in as many words — and nothing in `export-deny.txt` covered it.
  3. **gitleaks did not fire, and could not.** The cookie values are Iron/Hawk
     encoded blobs; they match no secret-detection rule. `verify-all.sh` ran its
     tracked-snapshot scan over this file repeatedly and passed, correctly, on
     its own terms.

So content scanning was never going to catch this class. The FILENAME is the only
reliable signal, which is what this checks.

The mitigating fact, recorded so severity is not overstated later: every
session-bearing cookie had already EXPIRED — the `wos-auth-verifier-*` values
expired at 05:25 UTC, seventeen minutes before the 05:42 commit that published
them. No live session was exposed. That is luck about timing, not a property of
the process, and is exactly why the process now has a control.

WHERE IT RUNS, and why there are two placements rather than one:

  * over `git ls-files` in `verify-all.sh` — catches the file at the moment it is
    committed to the private repo, which is the earliest signal available.
  * over the BUILT EXPORT TREE in `build-public-export.sh`, before that tree gets
    a git history. This is the placement that matters, because the export tree is
    the artifact that actually becomes public, and the private-repo scan cannot
    see a file that some future ALLOW entry sweeps in. A guard on the thing that
    ships beats a guard on a thing that usually resembles it.

SCOPE IS DELIBERATELY NARROW — credential-shaped FILENAMES, nothing else. It is
not a secret scanner (gitleaks is, and it correctly saw nothing here) and it must
not grow into one: a guard that checks many things vaguely gets ignored, and the
one thing this checks precisely is the one thing that actually happened.

USAGE
  check-no-session-state-files.py            # scan tracked files
  check-no-session-state-files.py --tree DIR # scan a built export tree
  check-no-session-state-files.py --selftest # prove it BLOCKS
EXIT 0 clean · 1 a session-state file is present · 2 bad usage
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

# Deliberately broad on the NAME and narrow on nothing else. A dump is worth
# refusing whatever it is called, and a false positive here costs one rename.
PATTERNS = [
    re.compile(r"auth[-_]?state.*\.json$", re.IGNORECASE),
    re.compile(r"storage[-_]?state.*\.json$", re.IGNORECASE),
    # A path that is a Windows path is never a real repo path on this tree, and
    # it is the exact shape the original incident took.
    re.compile(r"(^|/)[A-Za-z]:[\\/]?Users", re.IGNORECASE),
    re.compile(r"(^|/)[A-Za-z]:[^/]*$"),
]


def offenders(paths: list[str]) -> list[str]:
    return [p for p in paths if any(rx.search(p) for rx in PATTERNS)]


def in_tree(root: str) -> list[str]:
    """Every file under `root`, relative — the export tree has no git yet."""
    base = pathlib.Path(root)
    if not base.is_dir():
        print(f"✗ not a directory: {root}")
        raise SystemExit(2)
    return [
        str(f.relative_to(base))
        for f in base.rglob("*")
        if f.is_file() and ".git/" not in f"{f.relative_to(base)}/"
    ]


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    ).stdout
    return [ln for ln in out.splitlines() if ln.strip()]


def selftest() -> int:
    planted = [
        "apps/web/C:UsersSanjeevtl-auth-state.json",  # the real one
        "e2e/auth-state.json",
        "apps/web/storage_state.json",
        "C:UsersSomeoneelse.json",
    ]
    clean = [
        "apps/web/package.json",
        "packages/ui/src/index.ts",
        "docs/state-of-the-union.md",
        "apps/web/app/api/settings/api-keys/route.ts",
    ]
    bad = offenders(planted)
    if len(bad) != len(planted):
        missed = set(planted) - set(bad)
        print(f"SELFTEST FAILED — did not catch: {sorted(missed)}")
        return 1
    fp = offenders(clean)
    if fp:
        print(f"SELFTEST FAILED — flagged clean paths: {fp}")
        return 1
    # The --tree mode is a SECOND code path, so proving the pattern list works
    # says nothing about whether the export placement blocks. Plant a real file
    # in a real temp tree and require a non-zero exit. A guard never observed
    # blocking on the path it is installed on is not a guard there (CLAUDE.md §1).
    import subprocess as _sp
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        (root / "apps" / "web").mkdir(parents=True)
        (root / "apps" / "web" / "package.json").write_text("{}")
        clean_rc = _sp.run(
            [sys.executable, __file__, "--tree", td],
            capture_output=True,
            text=True,
            check=False,
        ).returncode
        if clean_rc != 0:
            print(f"SELFTEST FAILED — --tree flagged a CLEAN tree (rc={clean_rc})")
            return 1
        (root / "apps" / "web" / "C:UsersSanjeevtl-auth-state.json").write_text("[]")
        dirty_rc = _sp.run(
            [sys.executable, __file__, "--tree", td],
            capture_output=True,
            text=True,
            check=False,
        ).returncode
        if dirty_rc == 0:
            print("SELFTEST FAILED — --tree PASSED a tree containing the real dump")
            return 1

    print(
        "SELFTEST PASSED — 4 planted dumps CAUGHT, 4 clean paths not flagged,\n"
        "  and --tree was OBSERVED passing a clean tree and BLOCKING a dirty one."
    )
    return 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    argv = sys.argv[1:]
    where = "tracked"
    if argv and argv[0] == "--tree":
        if len(argv) != 2:
            print(__doc__)
            return 2
        paths, where = in_tree(argv[1]), f"export tree {argv[1]}"
    elif argv:
        print(__doc__)
        return 2
    else:
        paths = tracked()
    bad = offenders(paths)
    if bad:
        print(f"✗ session-state / Windows-path file(s) in {where}:")
        for p in bad:
            print(f"    {p}")
        print(
            "\n  A browser storage-state dump carries live session cookies, and a new\n"
            "  file under an allowlisted export tree ships PUBLICLY by default.\n"
            "  Delete it and add the pattern to .gitignore; do not add it to\n"
            "  export-deny.txt — omission is not the control here, not existing is."
        )
        return 1
    print(f"OK — no session-state dumps in {where} ({len(paths)} files scanned).")
    print(
        "  LIMIT, stated: this is a FILENAME rule. A dump committed under an\n"
        "  innocuous name is invisible to it, and gitleaks cannot see the content\n"
        "  either (Iron-encoded values match no secret rule). The real control is\n"
        "  not writing them into the repo."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

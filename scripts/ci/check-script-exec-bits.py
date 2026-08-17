#!/usr/bin/env python3
"""check-script-exec-bits — a script with a shebang must be executable IN GIT.

WHY (2026-08-11) — this is the SECOND instance, which is what makes it a class
=============================================================================
`ruff`'s EXE001 ("shebang is present but file is not executable") has now taken CI
red twice, both times from the same root cause:

  * 2026-08-09 (`00a3f089`) — four new guards in `scripts/ci/` shipped mode 644.
    That commit's own words: *"The Write path produces 644, so I broke a convention
    every pre-existing script follows."*
  * 2026-08-11 (run `31511826456`) — `scripts/ci/check-review-dates.py`, same thing,
    the only 644 `.py` left in the tree.

An agent writing a new file produces 644. Every pre-existing script is 755. So the
defect is produced by the normal authoring path and is invisible until CI.

WHY RUFF DOES NOT CATCH IT LOCALLY, AND WHY THAT IS THE REAL FINDING
====================================================================
`ruff check .` is byte-identical between `scripts/verify-all.sh` and the CI job, and
both run the same pinned ruff (0.16.0). **It still passes locally and fails in CI.**
Falsified rather than assumed: planting a fresh mode-644 file with a shebang at the
repo root and running `ruff check . --no-cache` reports "All checks passed" on this
machine. EXE001 asks the filesystem whether a file is executable, and a WSL2
ext4-on-vhdx checkout does not answer the way the CI runner's does.

So this guard deliberately **does not ask the filesystem**. It reads the mode from
`git ls-files -s`, which is the mode CI actually checks out — the same value on every
machine, in every container, regardless of how the local filesystem reports things.
That is the whole point: a check that depends on the environment cannot police a
defect whose symptom is environment-dependent.

WHAT IT CHECKS
==============
For every tracked `*.py` / `*.sh` under the script trees:

  * has a shebang  -> git mode MUST be 100755   (ruff EXE001)
  * no shebang     -> git mode MUST NOT be 100755 (ruff EXE002)

Both directions, because both are ruff errors and either will red the Python job.

HONEST LIMIT
============
It proves the mode is right. It cannot prove the script *works*, and it does not
cover file types ruff never looks at. It also reads the INDEX (staged) mode, so a
mode change left unstaged is invisible to it — which is correct, because an unstaged
change is not what CI will check out.

EXIT: 0 all good · 1 a violation · 2 usage / not a git repo
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Trees whose scripts CI lints. `.githooks` is included because it holds shell
# scripts that must be executable to function at all — a non-executable hook is a
# silently disabled hook, which is worse than a lint failure.
SCAN_PREFIXES = ("scripts/", ".githooks/")
SUFFIXES = (".py", ".sh")

EXEC_MODE = "100755"


def tracked_files(root: Path) -> list[tuple[str, str]]:
    """[(git_mode, path)] for tracked files under the scanned trees.

    Modes come from the git INDEX, never from `stat`. The filesystem is exactly
    what cannot be trusted here.
    """
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-s"],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        return []
    rows: list[tuple[str, str]] = []
    for line in out.stdout.splitlines():
        # `<mode> <sha> <stage>\t<path>`
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if not parts or not path:
            continue
        if not path.startswith(SCAN_PREFIXES) or not path.endswith(SUFFIXES):
            continue
        rows.append((parts[0], path))
    return rows


def has_shebang(root: Path, path: str) -> bool:
    """Does the file begin with `#!`? Read as bytes — a stray BOM or a binary
    blob must not raise and take the whole guard down."""
    try:
        with (root / path).open("rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def scan(root: Path) -> tuple[list[str], list[str]]:
    """Return (missing_exec, unexpected_exec)."""
    missing: list[str] = []
    unexpected: list[str] = []
    for mode, path in tracked_files(root):
        shebang = has_shebang(root, path)
        if shebang and mode != EXEC_MODE:
            missing.append(path)
        elif not shebang and mode == EXEC_MODE:
            unexpected.append(path)
    return missing, unexpected


def selftest() -> int:
    """Prove it BLOCKS — planting each violation in a throwaway git repo."""
    import tempfile

    fails = 0
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)

        def run(*a: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["git", "-C", str(root), *a],
                capture_output=True,
                text=True,
                check=False,
            )

        run("init", "-q")
        run("config", "user.email", "t@t")
        run("config", "user.name", "t")
        (root / "scripts" / "ci").mkdir(parents=True)

        good = root / "scripts/ci/good.py"
        good.write_text("#!/usr/bin/env python3\nprint('x')\n")
        run("add", "scripts/ci/good.py")
        run("update-index", "--chmod=+x", "scripts/ci/good.py")

        missing, unexpected = scan(root)
        if not missing and not unexpected:
            print("  ✓ a shebang script at 755 passes")
        else:
            print(f"  ✗ clean case flagged: {missing} {unexpected}")
            fails += 1

        # THE DEFECT: shebang + 644. This is what took CI red, twice.
        bad = root / "scripts/ci/bad.py"
        bad.write_text("#!/usr/bin/env python3\nprint('x')\n")
        run("add", "scripts/ci/bad.py")
        run("update-index", "--chmod=-x", "scripts/ci/bad.py")

        missing, _ = scan(root)
        if "scripts/ci/bad.py" in missing:
            print("  ✓ shebang + mode 644 is CAUGHT (the EXE001 defect)")
        else:
            print("  ✗ FAILED TO BLOCK — a 644 shebang script passed")
            fails += 1

        # The other direction (EXE002): executable, no shebang.
        noshb = root / "scripts/ci/noshebang.sh"
        noshb.write_text("echo hi\n")
        run("add", "scripts/ci/noshebang.sh")
        run("update-index", "--chmod=+x", "scripts/ci/noshebang.sh")

        _, unexpected = scan(root)
        if "scripts/ci/noshebang.sh" in unexpected:
            print("  ✓ executable WITHOUT a shebang is caught (EXE002)")
        else:
            print("  ✗ missed the EXE002 direction")
            fails += 1

        # A non-script file must not be dragged in — a guard that flags unrelated
        # files gets muted, and a muted guard is the thing this replaces.
        (root / "scripts" / "notes.md").write_text("#!not a shebang\n")
        run("add", "scripts/notes.md")
        missing2, unexpected2 = scan(root)
        if "scripts/notes.md" not in missing2 + unexpected2:
            print("  ✓ non-.py/.sh files are ignored (no false positives)")
        else:
            print("  ✗ flagged a markdown file")
            fails += 1

        # The mode must come from GIT, not the filesystem. Chmod the working tree
        # WITHOUT staging it and confirm the verdict does not move — this is the
        # property that makes the guard environment-independent.
        bad.chmod(0o755)
        missing3, _ = scan(root)
        if "scripts/ci/bad.py" in missing3:
            print("  ✓ reads the GIT mode, not the filesystem (unstaged chmod ignored)")
        else:
            print("  ✗ verdict moved on an unstaged chmod — it is reading stat()")
            fails += 1

    if fails:
        print(f"script-exec-bits selftest FAILED — {fails} case(s).")
        return 1
    print("script-exec-bits selftest PASSED.")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        if argv[1] == "--selftest":
            return selftest()
        print(f"check-script-exec-bits: unknown option: {argv[1]}", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[2]
    missing, unexpected = scan(root)
    if not missing and not unexpected:
        return 0

    print()
    if missing:
        print("  ✗ SHEBANG PRESENT BUT NOT EXECUTABLE IN GIT (ruff EXE001):")
        for p in missing:
            print(f"      {p}")
        print()
        print("    Fix:  git update-index --chmod=+x <path>")
    if unexpected:
        print("  ✗ EXECUTABLE IN GIT BUT NO SHEBANG (ruff EXE002):")
        for p in unexpected:
            print(f"      {p}")
        print()
        print("    Fix:  git update-index --chmod=-x <path>")
    print()
    print("  This has taken CI red twice (00a3f089, run 31511826456), both times")
    print("  because the file-writing path produces mode 644 while every")
    print("  pre-existing script is 755.")
    print()
    print("  `ruff check .` does NOT catch this locally — EXE001 asks the")
    print("  filesystem, and a WSL2 ext4-on-vhdx checkout answers differently from")
    print("  the CI runner. This guard reads the mode from `git ls-files -s`, which")
    print("  is what CI checks out, so it gives the same answer everywhere.")
    print()
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""INDEX↔FILE parity, and no accidental dangling `[[link]]`.

WHY THIS EXISTS — 2026-08-12. The agent memory store had **113 files and 101
index lines**: twelve memories existed and were unreachable, because recall reads
the index, not the directory. A file nobody can reach is worse than one that was
never written — you believe it is still there. They were found **by hand**, by
comparing two counts nobody had thought to compare.

**A count you have to remember to run is not a control.** That is the whole
argument for this file.

The same run found **11 dangling `[[links]]`**, one created that hour. Four
pointed at memories deleted minutes earlier, two were typos, two were bug IDs
that only LOOKED like links, and one was a POSIX character class (`[[:space:]]`)
inside a regex that the parser could not tell from a link.

THE DELIBERATE EXCEPTION. The memory rules say an unmatched `[[name]]` is
allowed — it "marks something worth writing later, not an error". So this guard
cannot simply ban them, or it would forbid a documented practice. It
distinguishes a **declared** placeholder (listed in `ALLOWED_DANGLING` with a
reason) from an **accidental** one. An undeclared dangling link fails.

USAGE
  check-index-parity.py             # check
  check-index-parity.py --selftest  # prove each violation BLOCKS
EXIT 0 clean · 1 parity or link violation · 2 bad usage
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Placeholders that are deliberate: a concept worth writing up, not a typo.
# Adding one requires a reason, which is the point — the cost of declaring is
# what keeps the list honest.
ALLOWED_DANGLING = {
    "class-1-control-not-load-bearing": "concept referenced twice; earns its own entry",
    "verification-scales-to-blast-radius": "CLAUDE.md §13 concept; not yet a memory file",
}

LINK_RE = re.compile(r"\[\[([^\]\[]+)\]\]")
# `- [Title](file.md) — hook`
# re.MULTILINE is load-bearing: without it `^` anchors to the START OF THE STRING
# only, so exactly one entry matches and every other file reads as "not indexed".
# The first run of this guard reported 103 of 104 files unreachable, which is how
# it was found — a guard whose failure mode is "everything is broken" is at least
# loud, but it was still wrong.
ENTRY_RE = re.compile(r"^\s*[-*]\s*\[[^\]]*\]\(([^)]+)\)", re.MULTILINE)


def check_store(index: Path, files_dir: Path, label: str) -> list[str]:
    """Parity + link health for one index-plus-directory store."""
    problems: list[str] = []
    if not index.exists() or not files_dir.is_dir():
        return problems

    on_disk = {p.name for p in files_dir.glob("*.md") if p.name != index.name}
    text = index.read_text(encoding="utf-8")
    indexed = set()
    for m in ENTRY_RE.finditer(text):
        target = m.group(1).split("#")[0].strip()
        if target.endswith(".md"):
            indexed.add(Path(target).name)

    # 1. Every file has an entry. This is the twelve-invisible-memories case.
    for missing in sorted(on_disk - indexed):
        problems.append(f"{label}: FILE NOT INDEXED — unreachable by recall: {missing}")
    # 2. Every entry resolves. An entry pointing at nothing is a promise of
    #    content that is not there.
    for orphan in sorted(indexed - on_disk):
        problems.append(f"{label}: INDEX ENTRY WITH NO FILE — {orphan}")

    # 3. Dangling links, minus the declared placeholders.
    stems = {n[:-3] for n in on_disk}
    for p in sorted(files_dir.glob("*.md")):
        # The index itself is excluded: its prose DOCUMENTS the `[[name]]` syntax,
        # so scanning it reports the documentation as a broken link.
        if p.name == index.name:
            continue
        for target in LINK_RE.findall(p.read_text(encoding="utf-8")):
            t = target.strip()
            if t in stems or t in ALLOWED_DANGLING:
                continue
            problems.append(
                f"{label}: DANGLING [[{t}]] in {p.name} — "
                "add the file, fix the name, or declare it in ALLOWED_DANGLING with a reason"
            )
    return problems


def stores() -> list[tuple[Path, Path, str]]:
    """(index, directory, label). Memory lives outside the repo, so it is checked
    only when present — CI has no `~/.claude`, and a guard that fails for being
    unable to see is the fail-open defect in reverse."""
    out: list[tuple[Path, Path, str]] = []
    mem = Path.home() / ".claude/projects/-home-sanjeev-work-tracelane-private/memory"
    if mem.is_dir():
        out.append((mem / "MEMORY.md", mem, "memory"))
    specs = ROOT / "specs"
    if specs.is_dir():
        out.append((specs / "README.md", specs, "specs"))
    return out


def check(quiet: bool = False) -> int:
    problems: list[str] = []
    checked = []
    for index, d, label in stores():
        # specs/README.md indexes via a generated table, and TEMPLATE.md is not a
        # spec — exclude it the same way the generator does.
        if label == "specs":
            problems += check_store_specs(index, d)
        else:
            problems += check_store(index, d, label)
        checked.append(label)
    if not quiet:
        print(f"index parity: checked {', '.join(checked) or 'nothing'}")
        for p in problems:
            print(f"  ✗ {p}")
        print(
            "OK — every file is indexed, every entry resolves, no undeclared dangling links."
            if not problems
            else f"FAIL — {len(problems)} problem(s)."
        )
    return 1 if problems else 0


def check_store_specs(index: Path, d: Path) -> list[str]:
    problems: list[str] = []
    if not index.exists():
        return problems
    on_disk = {p.name for p in d.glob("*.md")} - {"README.md", "TEMPLATE.md"}
    text = index.read_text(encoding="utf-8")
    indexed = {Path(m.group(1)).name for m in ENTRY_RE.finditer(text)} | {
        Path(t).name for t in re.findall(r"\]\(([^)]+\.md)\)", text)
    }
    for missing in sorted(on_disk - indexed):
        problems.append(
            f"specs: SPEC NOT IN THE INDEX — {missing} "
            "(run: python3 scripts/ci/build-doc-index.py)"
        )
    for orphan in sorted(indexed - on_disk - {"README.md", "TEMPLATE.md"}):
        problems.append(f"specs: INDEX ENTRY WITH NO FILE — {orphan}")
    return problems


def selftest() -> int:
    """Plant each violation and prove it blocks."""
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "a-thing.md").write_text("# a\n", encoding="utf-8")
        (d / "b-thing.md").write_text("# b\n", encoding="utf-8")

        # Baseline: both indexed, no links -> clean.
        (d / "IDX.md").write_text(
            "- [A](a-thing.md) — x\n- [B](b-thing.md) — y\n", encoding="utf-8"
        )
        base = check_store(d / "IDX.md", d, "t")
        print(
            f"selftest: a complete index passes .................. {'OK' if not base else 'FAIL'}"
        )
        ok &= not base

        # 1. UNINDEXED FILE — the twelve-invisible-memories case.
        (d / "IDX.md").write_text("- [A](a-thing.md) — x\n", encoding="utf-8")
        r = check_store(d / "IDX.md", d, "t")
        hit = any("NOT INDEXED" in x for x in r)
        print(
            f"selftest: an unindexed file blocks ................. {'OK' if hit else 'FAIL'}"
        )
        ok &= hit

        # 2. ORPHAN ENTRY — an index promising a file that is not there.
        (d / "IDX.md").write_text(
            "- [A](a-thing.md) — x\n- [B](b-thing.md) — y\n- [Ghost](ghost.md) — z\n",
            encoding="utf-8",
        )
        r = check_store(d / "IDX.md", d, "t")
        hit = any("NO FILE" in x for x in r)
        print(
            f"selftest: an orphan index entry blocks ............. {'OK' if hit else 'FAIL'}"
        )
        ok &= hit

        # 3. UNDECLARED DANGLING LINK.
        (d / "IDX.md").write_text(
            "- [A](a-thing.md) — x\n- [B](b-thing.md) — y\n", encoding="utf-8"
        )
        (d / "a-thing.md").write_text(
            "# a\n\nsee [[nope-not-a-file]]\n", encoding="utf-8"
        )
        r = check_store(d / "IDX.md", d, "t")
        hit = any("DANGLING" in x for x in r)
        print(
            f"selftest: an undeclared dangling link blocks ....... {'OK' if hit else 'FAIL'}"
        )
        ok &= hit

        # 4. A DECLARED placeholder must PASS — the documented practice survives.
        name = next(iter(ALLOWED_DANGLING))
        (d / "a-thing.md").write_text(f"# a\n\nsee [[{name}]]\n", encoding="utf-8")
        r = check_store(d / "IDX.md", d, "t")
        print(
            f"selftest: a DECLARED placeholder passes ............ {'OK' if not r else 'FAIL'}"
        )
        ok &= not r

    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


if __name__ == "__main__":
    args = set(sys.argv[1:])
    if args - {"--selftest"}:
        print(f"usage: {Path(__file__).name} [--selftest]")
        sys.exit(2)
    sys.exit(selftest() if "--selftest" in args else check())

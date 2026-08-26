#!/usr/bin/env python3
"""Every current-state claim in a spec must carry a `file:line` anchor that RESOLVES.

WHY THIS EXISTS — 2026-08-12, three of four specs read in one session misdescribed
the code, and each one sent the build in the wrong direction before being caught:

  * `OBS-17` said "add-to-dataset from a production span", assuming a Datasets
    backend. There is none — 0 hits in `schema.ts`, 0 gateway routes, a
    `ComingSoon` stub. The spec described a feature on top of a store that does
    not exist.
  * `GWY-27` said "there is no indirection layer in front of
    `provider_id_for_model`". `GWY-39` had already built one. Taken literally,
    the obvious implementation would have threaded `tenant_id` through three
    delegates — the exact drift class the code comment there warns against.
  * `PLT-41` described building a notification path that was already built:
    the exactly-once claim, the event enum and the sender all existed.

**A spec that misdescribes today's code sends you building the wrong thing.**
Anchoring the claim to `file:line` does not make it true, but it makes it
*checkable*, and it makes drift visible the moment the file moves.

WHAT THIS GUARD CAN AND CANNOT DO — stated here and printed in its own output,
because a guard that implies more than it checks is worse than none:

  CAN:    prove the anchor RESOLVES — the file exists, and the line is in range.
  CANNOT: prove the CLAIM IS TRUE. Nothing mechanical reads "there is no
          indirection layer" and checks reality. `GWY-27`'s claim had no anchor
          at all; with one, a reader would at least have been sent to the
          function and seen the alias lookup on line one.

So this is a **completeness and freshness** gate, not a truth gate. The truth
half is review, and it stays review.

USAGE
  check-spec-anchors.py             # check every spec
  check-spec-anchors.py --selftest  # prove it BLOCKS a dangling anchor
EXIT 0 clean · 1 a claim is unanchored or an anchor does not resolve · 2 bad usage
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPECS = ROOT / "specs"

# The headings that assert something about the CODE AS IT IS TODAY. A spec may say
# anything it likes about the future; it may not describe the present without a
# pointer to it.
CLAIM_RE = re.compile(
    r"^\s*\*\*Today[.:]?\*\*|^\s*\|\s*\*\*Inventory state today\*\*", re.MULTILINE
)
# `path/to/file.rs:123`, `path:12-30`, or a bare path. Backticks optional.
# Alternation is LONGEST-FIRST on purpose: Python's `|` takes the first branch that
# matches, so `ts` before `tsx` truncates `TraceFlag.tsx` to `TraceFlag.ts` and the
# guard then reports a missing file that exists. Caught on this guard's first real run.
#
# EXTENDED 2026-08-18 with the FRONT-END extensions — `astro css scss html jsx json js
# cjs`. The list previously stopped at the backend's file types, which meant a spec about
# a UI surface could not anchor to the files it was actually about: every anchor into
# `apps/site/src/pages/index.astro` or `global.css` was invisible to this regex, the claim
# read as UNANCHORED, and the only way to pass the gate was to cite an unrelated `.toml`.
# A guard that makes the honest anchor impossible teaches authors to write a decorative
# one, which is worse than no gate — it manufactures exactly the false confidence §16 says
# the anchor exists to prevent. Found writing `SITE-02`.
#
# Ordering, per the LONGEST-FIRST rule above: `jsx` and `json` MUST precede `js`, or
# `Chart.jsx` truncates to `Chart.js` and re-creates the `.tsx` bug this comment records.
ANCHOR_RE = re.compile(
    r"`?([A-Za-z0-9_./-]+\.(?:astro|scss|json|jsx|tsx|html|toml|yaml|yml|cjs|mjs|css"
    r"|ts|rs|py|sql|js|yml|md|sh))(?::(\d+)(?:-(\d+))?)?`?"
)
SKIP = {"README.md", "TEMPLATE.md"}


def _show(p: Path) -> str:
    """Repo-relative when inside the repo; absolute otherwise (selftest tempdirs)."""
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def claim_blocks(text: str) -> list[tuple[int, str]]:
    """Each current-state claim with its 1-based line number.

    A claim is the `**Today.**` paragraph — from the marker to the next blank
    line — so an anchor anywhere in that paragraph counts. Requiring it on the
    same LINE would push authors to cram, which produces worse prose and no more
    truth.
    """
    out: list[tuple[int, str]] = []
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if not CLAIM_RE.match(ln):
            continue
        block = [ln]
        for nxt in lines[i + 1 :]:
            if not nxt.strip():
                break
            block.append(nxt)
        out.append((i + 1, "\n".join(block)))
    return out


def check_anchor(raw: str, line: str | None, end: str | None) -> str | None:
    """None if the anchor resolves; otherwise why it does not.

    `re.findall` yields `''` — not `None` — for an unmatched optional group, so
    both are normalised here. Caught by this guard's own selftest before it was
    trusted, which is the entire argument for writing the selftest first.
    """
    line = line or None
    end = end or None
    p = ROOT / raw
    if not p.exists():
        return f"file does not exist: {raw}"
    if line is None:
        return None  # a bare path is a weaker but valid anchor
    try:
        n = sum(1 for _ in p.open("rb"))
    except OSError as e:  # pragma: no cover
        return f"unreadable: {raw} ({e})"
    hi = int(end or line)
    if int(line) < 1 or hi > n:
        return f"{raw}:{line}{'-' + end if end else ''} is out of range (file has {n} lines)"
    return None


def check(spec_dir: Path = SPECS, quiet: bool = False) -> int:
    if not spec_dir.is_dir():
        if not quiet:
            print(f"no {spec_dir.relative_to(ROOT)}/ — nothing to check")
        return 0
    problems: list[str] = []
    claims = 0
    for f in sorted(spec_dir.glob("*.md")):
        if f.name in SKIP:
            continue
        text = f.read_text(encoding="utf-8")
        for lineno, block in claim_blocks(text):
            claims += 1
            anchors = ANCHOR_RE.findall(block)
            # `.md` self-references are not code anchors — a spec citing another
            # spec is prose, not evidence about the running system.
            anchors = [a for a in anchors if not a[0].endswith(".md")]
            # An ANCHOR is navigable evidence: it carries a path separator, or a
            # `:line`. A bare filename with neither — `tracelane.yaml`, `Cargo.toml`
            # — is a NAME being discussed, not a pointer into the tree, and you
            # cannot navigate to it. Treating one as an anchor produced a false
            # failure on GWY-27, which mentions the operator's optional
            # `tracelane.yaml` (a RUNTIME artifact, absent from the repo by design)
            # while carrying three real anchors in the same paragraph. Narrowing
            # the definition loses nothing: a bare name was never evidence.
            anchors = [a for a in anchors if "/" in a[0] or a[1]]
            if not anchors:
                problems.append(
                    f"{_show(f)}:{lineno} — current-state claim with NO code anchor\n"
                    f"    {block.splitlines()[0][:110]}"
                )
                continue
            for raw, ln, end in anchors:
                why = check_anchor(raw, ln, end)
                if why:
                    problems.append(f"{_show(f)}:{lineno} — {why}")
    if not quiet:
        print(f"spec anchors: {claims} current-state claim(s) across {spec_dir.name}/")
        for p in problems:
            print(f"  ✗ {p}")
        print(
            "\nNOTE, and it is the point: this proves each anchor RESOLVES — the file\n"
            "exists and the line is in range. It does NOT prove the claim is TRUE.\n"
            "Nothing mechanical can read 'there is no indirection layer' and check\n"
            "reality; that half is review and stays review."
        )
        print(
            "OK — every current-state claim is anchored."
            if not problems
            else f"FAIL — {len(problems)} problem(s)."
        )
    return 1 if problems else 0


def selftest() -> int:
    """Plant each violation and prove it BLOCKS. A guard never observed blocking
    is not a guard (CLAUDE.md §1)."""
    import shutil
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "specs"
        d.mkdir()

        # 1. A dangling anchor must FAIL.
        (d / "X1-dangling.md").write_text(
            "# `X1` — dangling\n\n**Today.** It works, see "
            "`crates/gateway/src/this_file_does_not_exist.rs:12`.\n",
            encoding="utf-8",
        )
        rc = check(d, quiet=True)
        print(
            f"selftest: dangling anchor blocks .................... {'OK' if rc == 1 else 'FAIL'}"
        )
        ok &= rc == 1

        # 2. An out-of-range line must FAIL — a file that shrank is drift too.
        shutil.rmtree(d)
        d.mkdir()
        (d / "X2-range.md").write_text(
            "# `X2` — out of range\n\n**Today.** See `Cargo.toml:999999`.\n",
            encoding="utf-8",
        )
        rc = check(d, quiet=True)
        print(
            f"selftest: out-of-range line blocks .................. {'OK' if rc == 1 else 'FAIL'}"
        )
        ok &= rc == 1

        # 3. An UNANCHORED claim must FAIL — this is GWY-27's exact shape.
        shutil.rmtree(d)
        d.mkdir()
        (d / "X3-unanchored.md").write_text(
            "# `X3` — unanchored\n\n**Today.** There is no indirection layer in front of it.\n",
            encoding="utf-8",
        )
        rc = check(d, quiet=True)
        print(
            f"selftest: unanchored claim blocks (the GWY-27 shape)  {'OK' if rc == 1 else 'FAIL'}"
        )
        ok &= rc == 1

        # 4. A RESOLVING anchor must PASS — or the guard is just a red light.
        shutil.rmtree(d)
        d.mkdir()
        (d / "X4-good.md").write_text(
            "# `X4` — good\n\n**Today.** See `Cargo.toml:1`.\n", encoding="utf-8"
        )
        rc = check(d, quiet=True)
        print(
            f"selftest: a resolving anchor passes ................. {'OK' if rc == 0 else 'FAIL'}"
        )
        ok &= rc == 0

    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


if __name__ == "__main__":
    args = set(sys.argv[1:])
    if args - {"--selftest"}:
        print(f"usage: {Path(__file__).name} [--selftest]")
        sys.exit(2)
    sys.exit(selftest() if "--selftest" in args else check())

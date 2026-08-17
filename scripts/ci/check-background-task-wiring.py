#!/usr/bin/env python3
"""Every `pub fn spawn_*` in the Rust crates must have a NON-TEST call site.

WHY THIS EXISTS (earned 2026-08-15, R21). `spawn_anchor_age_sweeper` was committed in
`70ea128c` fully built, documented, and unit-tested — and **nothing called it**. The
commit's own message said so, and it still reached the tip of `main` as the last thing
between R21 and a merge. A background task with no caller is the quietest possible
defect: the feature is absent, every test that covers the function still passes, and
`/health` is green because nothing is broken — nothing is *running*.

**Why no existing gate caught it, and could not have:**

  * `crates/gateway/{main.rs,lib.rs}` carry crate-wide `#![allow(dead_code, unused_imports)]`,
    so `cargo clippy -D warnings` cannot see an unreferenced `pub fn` in this crate. That
    allow is deliberate and is not going away.
  * `cargo-machete` checks unused *dependencies*, not unused functions.
  * `knip` (`verify-all.sh`) is the repo's only dead-code gate and is scoped to `apps/web`
    — TypeScript, not Rust.
  * Every other `server.rs` guard checks content *within* a named function
    (`check-hot-path-logging`, `check-post-ledger-span-emit`, `check-span-publish-ordering`).
    None asks whether a function is *reached*.

So a `spawn_*` with zero call sites passed every job in `ci.yml` and every gate in
`verify-all.sh`. This closes that.

**Scope, stated honestly.** This proves a call site EXISTS in non-test source. It does not
prove the call is reachable at runtime, that it is on a path the process actually takes,
or that the spawned task does anything useful. Those are review, not machinery. It is
aimed at exactly one failure — built, tested, never wired — because that is the one that
happened.

**What does NOT count as a call site**, and each is a real way the naive version passes:
  * the definition itself;
  * any occurrence inside a `//` or `/* */` comment or a `///` doc comment — a doc comment
    that says "call `spawn_foo` at startup" is the single most likely false green here,
    because it is what a careful author writes *instead of* wiring it;
  * any occurrence inside a `#[cfg(test)]` module — a task called only from its own test is
    the precise shape of the defect, not a defence against it.

Exit codes:  0 pass · 1 violation(s) found · 2 CANNOT DETERMINE / bad usage.

    python3 scripts/ci/check-background-task-wiring.py
    python3 scripts/ci/check-background-task-wiring.py --selftest
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Crates whose `pub fn spawn_*` must be wired. Each is a long-running process crate where
# an unwired background task is a silently missing feature.
CRATE_DIRS = [
    Path("crates/gateway/src"),
    Path("crates/ingest/src"),
    Path("crates/shared/src"),
]

RE_DEF = re.compile(r"^\s*pub(?:\s+async)?\s+fn\s+(spawn_\w+)\s*[(<]", re.MULTILINE)

# A file-level `#![cfg(test)]` INNER attribute makes the whole module test-only, so its
# `spawn_*` need no production wiring and its call sites must not count as one. This is
# not an allowlist — it is the language's own scoping, and missing it is a false positive:
# the guard's first run against the real tree flagged `crates/ingest/src/spire_mock.rs`,
# an in-process mock SPIRE server that is `#![cfg(test)]` at line 10 and correctly called
# only from `spire_client.rs` and `tls.rs` test modules.
RE_FILE_LEVEL_CFG_TEST = re.compile(r"^\s*#!\[cfg\(test\)\]", re.MULTILINE)


def strip_comments(src: str) -> str:
    """Blank out `//`-to-EOL and `/* */` comments, preserving line structure.

    Character-by-character rather than regex, because a regex that strips `//…` will also
    eat the `//` inside a string literal such as a URL — and `"http://…"` appears all over
    this tree. Getting that wrong makes the guard silently scan less than it reports.
    """
    out = []
    i, n = 0, len(src)
    in_line_comment = in_block_comment = in_string = False
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                out.append(c)
            else:
                out.append(" ")
        elif in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
        elif in_string:
            out.append(c)
            if c == "\\":
                if i + 1 < n:
                    out.append(src[i + 1])
                    i += 2
                    continue
            elif c == '"':
                in_string = False
        else:
            if c == "/" and nxt == "/":
                in_line_comment = True
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                in_block_comment = True
                out.append("  ")
                i += 2
                continue
            if c == '"':
                in_string = True
            out.append(c)
        i += 1
    return "".join(out)


def strip_test_modules(src: str) -> str:
    """Blank out every `#[cfg(test)] mod … { … }` body by brace matching.

    A `spawn_*` invoked only from its own unit test is the defect, not the fix, so those
    call sites must not count. Brace matching rather than a line heuristic because these
    modules are hundreds of lines long and contain nested braces and string literals.
    Runs AFTER `strip_comments`, so braces inside comments cannot unbalance the count.
    """
    out = list(src)
    for m in re.finditer(r"#\[cfg\(test\)\]", src):
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        # Only treat it as a module/block if what sits between is short — a `#[cfg(test)]`
        # on a single `fn` is fine to blank too, but we must not run away to a distant `{`.
        if "}" in src[m.end() : brace] or (brace - m.end()) > 200:
            continue
        depth, i, n = 0, brace, len(src)
        while i < n:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            continue  # unbalanced; leave it rather than blank the rest of the file
        for j in range(m.start(), min(i + 1, n)):
            if out[j] != "\n":
                out[j] = " "
    return "".join(out)


def collect(root: Path) -> tuple[dict[str, tuple[str, int]], dict[str, str]]:
    """Return (definitions, scannable_sources).

    definitions: name -> (relative path, 1-indexed line)
    scannable_sources: relative path -> source with comments and test modules removed
    """
    defs: dict[str, tuple[str, int]] = {}
    sources: dict[str, str] = {}
    for crate_dir in CRATE_DIRS:
        d = root / crate_dir
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*.rs")):
            raw = f.read_text(encoding="utf-8", errors="replace")
            rel = str(f.relative_to(root))
            clean = strip_comments(raw)
            if RE_FILE_LEVEL_CFG_TEST.search(clean):
                continue  # whole file is test-only; neither defines nor wires prod tasks
            clean = strip_test_modules(clean)
            sources[rel] = clean
            for m in RE_DEF.finditer(clean):
                # Anchor on the NAME (group 1), never on `m.start()`. `^\s*` can consume
                # the preceding newline, so the match begins on the LINE BEFORE the
                # definition — and then the definition's own `spawn_x(` no longer matches
                # the "skip the definition itself" line test and is counted as a call
                # site, so every unwired task passes. The selftest caught exactly that.
                defs[m.group(1)] = (rel, clean[: m.start(1)].count("\n") + 1)
    return defs, sources


def check(root: Path) -> list[str]:
    defs, sources = collect(root)
    if not defs:
        # LOUD, never a silent green: if the definition scan finds nothing, the guard is
        # checking nothing, and that is indistinguishable from a pass.
        raise LookupError(
            "no `pub fn spawn_*` found in "
            + ", ".join(str(c) for c in CRATE_DIRS)
            + " — the scan is not reaching the source"
        )
    violations = []
    for name, (def_file, def_line) in sorted(defs.items()):
        call_re = re.compile(r"\b" + re.escape(name) + r"\s*\(")
        found = False
        for rel, clean in sources.items():
            for m in call_re.finditer(clean):
                line = clean[: m.start()].count("\n") + 1
                if rel == def_file and line == def_line:
                    continue  # the definition itself
                found = True
                break
            if found:
                break
        if not found:
            violations.append(
                f"{def_file}:{def_line}: `{name}` has NO non-test call site — "
                f"the task is built but never started"
            )
    return violations


# --------------------------------------------------------------------------- selftest

_CLEAN = """
pub fn spawn_worker(x: u32) {
    tokio::spawn(async move { let _ = x; });
}
pub async fn run() {
    spawn_worker(1);
}
"""

_UNWIRED = """
pub fn spawn_worker(x: u32) {
    tokio::spawn(async move { let _ = x; });
}
pub async fn run() {
    let _ = 1;
}
"""

_ONLY_IN_COMMENT = """
pub fn spawn_worker(x: u32) {
    tokio::spawn(async move { let _ = x; });
}
pub async fn run() {
    // remember to call spawn_worker(1) here at startup
    let _ = 1;
}
"""

_ONLY_IN_TEST = """
pub fn spawn_worker(x: u32) {
    tokio::spawn(async move { let _ = x; });
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() { spawn_worker(1); }
}
"""

# A whole-file `#![cfg(test)]` module. Its `spawn_*` is called only from other test
# modules and that is correct — flagging it would be a false positive, which is what the
# guard did on its first real run (`crates/ingest/src/spire_mock.rs`).
_FILE_LEVEL_CFG_TEST = """
#![cfg(test)]
pub async fn spawn_mock_thing(x: u32) -> u32 { x }
"""

_URL_NOT_A_COMMENT = """
pub fn spawn_worker(x: u32) {
    let _ = "https://example.com/x"; let _ = x;
}
pub async fn run() {
    spawn_worker(1);
}
"""


def selftest(root: Path) -> int:
    import shutil
    import subprocess
    import tempfile

    before = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout

    cases = [
        ("clean_PASSES", _CLEAN, 0),
        ("unwired_BLOCKS", _UNWIRED, 1),
        ("call_only_in_comment_BLOCKS", _ONLY_IN_COMMENT, 1),
        ("call_only_in_cfg_test_BLOCKS", _ONLY_IN_TEST, 1),
        ("url_slashes_are_not_a_comment_PASSES", _URL_NOT_A_COMMENT, 0),
        # want 2: the file is skipped, so NO definitions remain and the guard must be
        # LOUD about seeing nothing rather than reporting a pass over an empty scan.
        ("file_level_cfg_test_is_SKIPPED", _FILE_LEVEL_CFG_TEST, 2),
    ]
    failures = 0
    for name, src, want in cases:
        tmp = Path(tempfile.mkdtemp(prefix="bgwire-"))
        try:
            d = tmp / "crates" / "gateway" / "src"
            d.mkdir(parents=True)
            (d / "lib.rs").write_text(src)
            try:
                got = 1 if check(tmp) else 0
            except LookupError:
                got = 2
            mark = "✓" if got == want else "✗"
            if got != want:
                failures += 1
            print(f"  {mark} {name} (want {want}, got {got})")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # The scan reaching nothing must be LOUD, not a pass.
    empty = Path(tempfile.mkdtemp(prefix="bgwire-empty-"))
    try:
        try:
            check(empty)
            print("  ✗ empty_tree_is_LOUD (expected LookupError, got a pass)")
            failures += 1
        except LookupError:
            print("  ✓ empty_tree_is_LOUD")
    finally:
        shutil.rmtree(empty, ignore_errors=True)

    after = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    if before != after:
        print("  ✗ tree_restored — selftest left the working tree modified")
        failures += 1
    else:
        print("  ✓ tree_restored")

    if failures:
        print(f"selftest FAILED: {failures} case(s)")
        return 1
    print(
        "selftest OK: the guard blocks an unwired task, a comment-only call, and a "
        "test-only call; and it is loud when it can see nothing"
    )
    return 0


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[2]
    args = argv[1:]
    if args == ["--selftest"]:
        return selftest(root)
    if args:
        print(f"usage: {Path(argv[0]).name} [--selftest]", file=sys.stderr)
        return 2
    try:
        violations = check(root)
    except LookupError as e:
        print(f"CANNOT DETERMINE: {e}", file=sys.stderr)
        return 2
    if violations:
        print("Background tasks that are built but never started:\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        print(
            "\nWire it beside the other spawned tasks in the process's setup function, "
            "or delete it.\nA task with no caller is a feature that is absent while every "
            "test covering it passes.",
            file=sys.stderr,
        )
        return 1
    defs, _ = collect(root)
    print(f"background-task wiring: {len(defs)} `pub fn spawn_*` checked, all wired")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

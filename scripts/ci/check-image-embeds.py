#!/usr/bin/env python3
"""Every file a release binary embeds from OUTSIDE its crate reaches the image build.

WHY (2026-09-29, deploy of `10445754`'s parent). Capture Waves 0-1 added
`include_str!("../../../apps/web/db/plans.v3.json")` to `crates/shared`. The full gate
compiled it on a checkout that has the whole repo, and was green. The on-node Docker
build then failed — `plans.v3.json` was in none of the three things between the repo
and `cargo build --release` inside the image:

  1. the deploy tarball (`scripts/deploy/gateway.sh`'s `tar czf /tmp/gw-src.tgz …` list),
  2. the Docker build context (`.dockerignore` excludes `apps/` and re-includes by `!`),
  3. the Dockerfile's `COPY` lines (each image copies only what it names).

Prod was untouched only because the build failed before the swap. The class is "an
embed that the workspace build sees and the image build does not", so this guard checks
every cross-crate embed of every crate each Dockerfile builds, against all three.

WHAT IS AN EMBED. `include_str!` / `include_bytes!` in PRODUCTION code — `#[cfg(test)]`
items are blanked first (a release build never compiles them), using the same walker as
`check-banned-patterns.py`. The path is resolved against the including file's directory;
one that stays inside the crate is covered by `COPY crates/` and is not checked.

HONEST LIMITS. `build.rs` reads, `include!` of generated code, `concat!(env!(…))` paths and
runtime file reads are not seen. A Dockerfile's crate set is read from its
`cargo build … -p <pkg>` and the path dependencies in each Cargo.toml, not from
`cargo metadata`.

Usage: check-image-embeds.py [--selftest] [--root DIR]
"""

from __future__ import annotations

import fnmatch
import importlib.util
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("bp", HERE / "check-banned-patterns.py")
assert _spec and _spec.loader
_bp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_bp)

DOCKERFILES = [
    "infra/docker/gateway.Dockerfile",
    "infra/docker/ingest.Dockerfile",
    "Dockerfile",
]
DEPLOY_SCRIPT = "scripts/deploy/gateway.sh"
EMBED = re.compile(r"include_(?:str|bytes)!\s*\(")
LIT = re.compile(r'"([^"]+)"')


def crate_dirs(root: Path) -> dict[str, Path]:
    """package name -> crate dir, for every Cargo.toml under crates/ and packages/."""
    out: dict[str, Path] = {}
    for toml in list(root.glob("crates/*/Cargo.toml")) + list(
        root.glob("packages/*/Cargo.toml")
    ):
        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', toml.read_text(), re.MULTILINE)
        if m:
            out[m.group(1)] = toml.parent
    return out


def closure(pkg_dir: Path) -> set[Path]:
    seen: set[Path] = set()
    stack = [pkg_dir.resolve()]
    while stack:
        d = stack.pop()
        if d in seen or not (d / "Cargo.toml").exists():
            continue
        seen.add(d)
        for dep in re.findall(r'path\s*=\s*"([^"]+)"', (d / "Cargo.toml").read_text()):
            p = (d / dep).resolve()
            if (p / "Cargo.toml").exists():
                stack.append(p)
    return seen


def embeds(root: Path, crate: Path) -> dict[str, str]:
    """repo-relative embedded path OUTSIDE the crate -> 'file:line' of its first use."""
    out: dict[str, str] = {}
    # `src/` only: `tests/`, `benches/` and `examples/` are never part of a release build.
    for rs in sorted((crate / "src").rglob("*.rs")):
        raw = rs.read_text(errors="replace")
        prod = _bp.production_part(_bp.strip_comments_and_strings(raw)).split("\n")
        raw_lines = raw.split("\n")
        for i, line in enumerate(prod):
            if not EMBED.search(line):
                continue
            window = "\n".join(
                raw_lines[i : i + 3]
            )  # the literal may sit on the next line
            em = EMBED.search(window)
            m = LIT.search(window[em.end() :]) if em else None
            if not m:
                continue
            target = (rs.parent / m.group(1)).resolve()
            try:
                target.relative_to(crate.resolve())
                continue  # inside the crate: `COPY crates/` covers it
            except ValueError:
                pass
            rel = os.path.relpath(target, root.resolve())
            out.setdefault(rel, f"{rs.relative_to(root)}:{i + 1}")
    return out


def covered_by(path: str, sources: list[str]) -> bool:
    for s in sources:
        s = s.rstrip("/")
        if s in (".", "") or path == s or path.startswith(s + "/"):
            return True
    return False


def _match(path: str, pat: str) -> bool:
    """Go `filepath.Match` per segment (`*` never crosses `/`), plus `**` for any depth."""
    ps, qs = path.split("/"), pat.split("/")

    def go(i: int, j: int) -> bool:
        if j == len(qs):
            return i == len(ps)
        if qs[j] == "**":
            return any(go(k, j + 1) for k in range(i, len(ps) + 1))
        return i < len(ps) and fnmatch.fnmatchcase(ps[i], qs[j]) and go(i + 1, j + 1)

    return go(0, 0)


def dockerignored(root: Path, path: str) -> bool:
    """Docker semantics: patterns in order, the LAST match wins, `!` re-includes; a
    pattern matching a parent directory excludes everything under it."""
    f = root / ".dockerignore"
    if not f.exists():
        return False
    parts = path.split("/")
    prefixes = ["/".join(parts[: k + 1]) for k in range(len(parts))]
    ignored = False
    for line in f.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = (line[1:] if neg else line).strip("/")
        hit = any(_match(c, pat) for c in prefixes)
        if hit:
            ignored = not neg
    return ignored


def check(root: Path) -> list[str]:
    failures: list[str] = []
    crates = crate_dirs(root)
    tar_line = next(
        (
            l
            for l in (root / DEPLOY_SCRIPT).read_text().splitlines()
            if "tar czf" in l and "gw-src" in l
        ),
        "",
    )
    tar_sources = tar_line.split("gw-src.tgz", 1)[1].split() if tar_line else []
    if not tar_sources:
        failures.append(
            f"{DEPLOY_SCRIPT}: could not find the `tar czf …gw-src.tgz` source list — refusing to assume it is complete"
        )
    all_embeds: dict[str, str] = {}
    for df in DOCKERFILES:
        p = root / df
        if not p.exists():
            continue
        text = p.read_text()
        pkgs = re.findall(r"cargo build[^\n]*?-p\s+([\w-]+)", text)
        if not pkgs:
            failures.append(
                f"{df}: no `cargo build … -p <pkg>` found — cannot tell which crates it embeds for"
            )
            continue
        copies: list[str] = []
        for m in re.finditer(r"^COPY\s+(?!--from)(.+)$", text, re.MULTILINE):
            toks = [t for t in m.group(1).split() if not t.startswith("--")]
            copies.extend(toks[:-1])
        dirs: set[Path] = set()
        for pkg in pkgs:
            if pkg not in crates:
                failures.append(
                    f"{df}: builds `{pkg}`, which no Cargo.toml under crates/ or packages/ names"
                )
                continue
            dirs |= closure(crates[pkg])
        for d in sorted(dirs):
            for path, where in embeds(root, d).items():
                all_embeds.setdefault(path, where)
                if not covered_by(path, copies):
                    failures.append(
                        f"{df}: `{path}` (embedded at {where}) is never COPY'd into the build stage"
                    )
    for path, where in sorted(all_embeds.items()):
        if dockerignored(root, path):
            failures.append(
                f".dockerignore: `{path}` (embedded at {where}) is excluded from the build context — add `!{path}`"
            )
        if tar_sources and not covered_by(path, tar_sources):
            failures.append(
                f"{DEPLOY_SCRIPT}: `{path}` (embedded at {where}) is not in the deploy tarball list"
            )
    return failures


def _plant(
    root: Path, *, copy: bool, reinclude: bool, tar: bool, test_only: bool = False
) -> None:
    (root / "crates/app/src").mkdir(parents=True, exist_ok=True)
    (root / "crates/lib/src").mkdir(parents=True, exist_ok=True)
    (root / "apps/web/db").mkdir(parents=True, exist_ok=True)
    (root / "infra/docker").mkdir(parents=True, exist_ok=True)
    (root / "scripts/deploy").mkdir(parents=True, exist_ok=True)
    (root / "apps/web/db/table.json").write_text("{}")
    (root / "crates/app/Cargo.toml").write_text(
        '[package]\nname = "app"\n[dependencies]\nlib = { path = "../lib" }\n'
    )
    (root / "crates/lib/Cargo.toml").write_text('[package]\nname = "lib"\n')
    (root / "crates/app/src/main.rs").write_text(
        'const P: &str = include_str!("../local.txt");\nfn main() {}\n'
    )
    body = 'include_str!(\n    "../../../apps/web/db/table.json"\n)'
    if test_only:
        (root / "crates/lib/src/lib.rs").write_text(
            f"#[cfg(test)]\nmod tests {{ fn t() {{ let _ = {body}; }} }}\n"
        )
    else:
        (root / "crates/lib/src/lib.rs").write_text(
            f"pub fn t() -> &'static str {{ {body} }}\n"
        )
    (root / "infra/docker/gateway.Dockerfile").write_text(
        "COPY crates/ crates/\n"
        + ("COPY apps/web/db/table.json apps/web/db/table.json\n" if copy else "")
        + "RUN cargo build --release -p app\n"
    )
    (root / ".dockerignore").write_text(
        "apps/\n" + ("!apps/web/db/table.json\n" if reinclude else "")
    )
    (root / DEPLOY_SCRIPT).write_text(
        "tar czf /tmp/gw-src.tgz Cargo.toml crates"
        + (" apps/web/db/table.json" if tar else "")
        + " infra\n"
    )


def selftest() -> int:
    cases = [
        (
            "all three present -> PASS",
            {"copy": True, "reinclude": True, "tar": True},
            0,
            None,
        ),
        (
            "missing COPY -> BLOCK",
            {"copy": False, "reinclude": True, "tar": True},
            1,
            "never COPY'd",
        ),
        (
            "excluded by .dockerignore -> BLOCK",
            {"copy": True, "reinclude": False, "tar": True},
            1,
            ".dockerignore",
        ),
        (
            "missing from deploy tar -> BLOCK",
            {"copy": True, "reinclude": True, "tar": False},
            1,
            "deploy tarball",
        ),
        (
            "embed in a path DEPENDENCY is followed",
            {"copy": False, "reinclude": True, "tar": True},
            1,
            "crates/lib/src/lib.rs",
        ),
        (
            "a #[cfg(test)]-only embed is not required",
            {"copy": False, "reinclude": False, "tar": False, "test_only": True},
            0,
            None,
        ),
    ]
    bad = 0
    for name, kw, want_fail, needle in cases:
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _plant(root, **kw)
            f = check(root)
            got = 1 if f else 0
            ok = got == want_fail and (needle is None or any(needle in x for x in f))
            print(
                f"selftest: {'✓' if ok else '✗'} {name}"
                + ("" if ok else f"  (got {f})")
            )
            bad += 0 if ok else 1
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[2]
    args = list(argv)
    if "--root" in args:
        i = args.index("--root")
        root = Path(args[i + 1]).resolve()
        del args[i : i + 2]
    if args == ["--selftest"]:
        return selftest()
    if args:
        print(
            f"usage: {Path(__file__).name} [--selftest] [--root DIR]", file=sys.stderr
        )
        return 2
    failures = check(root)
    for f in failures:
        print(f"✗ {f}")
    if failures:
        print(
            "image embeds: an embedded file the image build cannot see fails the on-node build (2026-09-29)."
        )
        return 1
    print(
        "image embeds: every cross-crate include_str!/include_bytes! reaches all three image inputs ✓"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

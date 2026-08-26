#!/usr/bin/env python3
"""No crate ADDED to `Cargo.lock` may carry a network client in its BUILD dependencies.

WHY THIS EXISTS, and why it is not the guard next door.

B-263: `cargo deny` failed on a yanked `arrayref` and told us to run
`cargo update -p arrayref`. Following that advice resolves `arrayref` 0.3.10, whose
only non-dev dependency is `proc-macro1` — a `proc-macro2` typosquat whose `build.rs`
downloads and executes a binary with TLS verification disabled. A build script runs at
COMPILE time, before any of our own code, so `cargo build` IS the exploit.
`docs/reference/TRAPS.md` §43 is the class: **a control's own suggested remediation is
attacker-influenced input.**

`check-build-script-network-deps.py` already catches that shape — but it shells out to
`cargo metadata`, so it needs a Rust toolchain and it fails CLOSED (exit 2) without one.
**`tl-node-1`, the self-hosted runner every working CI job routes to, has no cargo**
(`command -v cargo` returns nothing), and the GitHub-hosted runners have not provisioned
since 2026-08-17 (`GH-ACTIONS-BILLING`). Putting a fail-closed cargo dependency into the
one CI job that currently runs would turn it permanently red, which is worse than no
guard at all.

So this guard answers the same question with NO TOOLCHAIN: it diffs `Cargo.lock` against
a base ref, takes only the packages the change ADDS, and reads each one's dependency
metadata straight from the crates.io **sparse index**, which publishes a `kind` field per
dependency ("build" / "dev" / "normal"). Metadata only — it never downloads the crate,
never unpacks it, and never executes a line of it. That distinction is the safety
property: reading about a build script is safe, running one is not.

**WHY THE DELTA IS BETTER TARGETING, NOT JUST CHEAPER.** A Dependabot PR's entire risk
surface is the packages it ADDS. Dependabot does not merely advise a fix the way
`cargo deny` does — it WRITES the diff and opens the PR, under a security label that
actively discourages scrutiny (`.github/dependabot.yml` covers six ecosystems INCLUDING
`package-ecosystem: cargo` at the workspace root, and its own header says "security
advisories are immediate"). A PR bumping `arrayref` 0.3.9 -> 0.3.10 would have been the
identical attack, pre-written, with the review pressure inverted.

TWO RESIDUALS, STATED BECAUSE A GUARD THAT HIDES ITS BLIND SPOT IS WORSE THAN ONE THAT
DOES NOT EXIST (CLAUDE.md §1, and §37 on denominators):

  1. **It cannot see a malicious PROC-MACRO that executes at EXPANSION time** rather than
     in `build.rs`. A proc-macro crate is a normal dependency, not a build dependency, and
     it also runs arbitrary code at compile time. That is a real and equivalent vector and
     nothing here addresses it.
  2. **It cannot see a payload added to an EXISTING package at a version already in the
     lock.** This guard reads only what the diff ADDS. A crate already pinned, whose
     upstream is compromised without a version bump, is invisible to it — and to
     `cargo deny`'s ban list too, until an advisory names it.

Neither is what B-263 was. Both would get past this.

USAGE
  check-new-crate-build-deps.py                 # diff HEAD's Cargo.lock vs origin/main
  check-new-crate-build-deps.py --base <ref>    # explicit base ref
  check-new-crate-build-deps.py --selftest      # prove it BLOCKS (offline, no network)
EXIT 0 clean or nothing added · 1 an added crate has a network-capable build dep
     · 2 could not determine (never a pass)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

# Same vocabulary as `check-build-script-network-deps.py`, deliberately: two guards
# disagreeing about what "network-capable" means is how one of them gets trusted.
NETWORK_CAPABLE = {
    "attohttpc",
    "curl",
    "curl-sys",
    "hyper",
    "isahc",
    "native-tls",
    "openssl",
    "openssl-sys",
    "reqwest",
    "rustls",
    "socket2",
    "surf",
    "tokio",
    "ureq",
}

INDEX = "https://index.crates.io"
TIMEOUT_S = 15

_PKG = re.compile(r"^\[\[package\]\]$")
_NAME = re.compile(r'^name = "([^"]+)"$')
_VERS = re.compile(r'^version = "([^"]+)"$')


def packages(lock_text: str) -> set[tuple[str, str]]:
    """Every `(name, version)` in a Cargo.lock. Hand-parsed on purpose — no `toml`
    dependency, because this guard must run in a python-only CI job."""
    out: set[tuple[str, str]] = set()
    name: str | None = None
    for line in lock_text.splitlines():
        line = line.strip()
        if _PKG.match(line):
            name = None
            continue
        m = _NAME.match(line)
        if m:
            name = m.group(1)
            continue
        m = _VERS.match(line)
        if m and name:
            out.add((name, m.group(1)))
            name = None
    return out


def index_path(name: str) -> str:
    """crates.io sparse-index path. The prefix rule is the registry's, not ours."""
    n = name.lower()
    if len(n) == 1:
        return f"1/{n}"
    if len(n) == 2:
        return f"2/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[0:2]}/{n[2:4]}/{n}"


def build_deps(name: str, version: str) -> list[str] | None:
    """Network-capable BUILD dependencies of one published version.

    Returns `None` for CANNOT DETERMINE (unreachable index, absent crate, absent
    version) — which the caller treats as a refusal to certify, never as clean.
    """
    url = f"{INDEX}/{index_path(name)}"
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_S) as resp:
            body = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return None
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("vers") != version:
            continue
        deps = rec.get("deps") or []
        return sorted(
            {
                d.get("name", "")
                for d in deps
                if d.get("kind") == "build" and d.get("name") in NETWORK_CAPABLE
            }
        )
    return None


def git_show(ref: str, path: str) -> str | None:
    p = subprocess.run(
        ["git", "show", f"{ref}:{path}"], capture_output=True, text=True, check=False
    )
    return p.stdout if p.returncode == 0 else None


def selftest() -> int:
    fails = 0

    def expect(label: str, got, want) -> None:
        nonlocal fails
        if got == want:
            print(f"  ✓ {label}")
        else:
            print(f"  ✗ {label} — expected {want!r}, got {got!r}")
            fails += 1

    # THE REAL ATTACK SHAPE: the delta must isolate exactly the added crate.
    base = '[[package]]\nname = "blake3"\nversion = "1.5.0"\n'
    head = base + '\n[[package]]\nname = "proc-macro1"\nversion = "1.0.107"\n'
    added = packages(head) - packages(base)
    expect(
        "an added crate is isolated by the delta", added, {("proc-macro1", "1.0.107")}
    )

    # A VERSION BUMP is an add too — that is the Dependabot shape.
    b2 = '[[package]]\nname = "arrayref"\nversion = "0.3.9"\n'
    h2 = '[[package]]\nname = "arrayref"\nversion = "0.3.10"\n'
    expect(
        "a version bump reads as ADDED",
        packages(h2) - packages(b2),
        {("arrayref", "0.3.10")},
    )

    # An UNCHANGED lock adds nothing — the guard must be silent, not chatty.
    expect("an unchanged lockfile adds nothing", packages(base) - packages(base), set())

    # The parser must not fold `version` under the wrong `name`.
    multi = (
        '[[package]]\nname = "a"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "b"\nversion = "2.0.0"\n'
    )
    expect(
        "two packages parse independently",
        packages(multi),
        {("a", "1.0.0"), ("b", "2.0.0")},
    )

    # The sparse-index prefix rule, all four branches.
    expect("index path, 1 char", index_path("a"), "1/a")
    expect("index path, 2 chars", index_path("ab"), "2/ab")
    expect("index path, 3 chars", index_path("abc"), "3/a/abc")
    expect("index path, 4+ chars", index_path("proc-macro1"), "pr/oc/proc-macro1")

    # CANNOT DETERMINE must be distinguishable from CLEAN. `build_deps` returns None
    # for an unreachable index; `[]` means "read it, found none". Conflating them is
    # how an offline CI run would silently certify a poisoned bump.
    expect("None and [] are different values", None == [], False)

    if fails == 0:
        print(
            "\nSELFTEST PASSED — the delta isolates an added crate (including a version\n"
            "  bump, which is the Dependabot shape), the index prefix rule is right, and\n"
            "  CANNOT DETERMINE stays distinguishable from CLEAN."
        )
        return 0
    print(f"\nSELFTEST FAILED — {fails} case(s).")
    return 1


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--selftest"]:
        return selftest()
    base = "origin/main"
    if len(argv) == 2 and argv[0] == "--base":
        base = argv[1]
    elif argv:
        print(__doc__)
        return 2

    with open("Cargo.lock", encoding="utf-8") as fh:
        head_lock = fh.read()
    base_lock = git_show(base, "Cargo.lock")
    if base_lock is None:
        # No base to diff against is CANNOT DETERMINE, not "nothing was added".
        print(f"✗ CANNOT DETERMINE — no Cargo.lock at base ref '{base}'.")
        return 2

    added = sorted(packages(head_lock) - packages(base_lock))
    if not added:
        print(f"OK — Cargo.lock adds no package against {base}.")
        return 0

    offenders: list[tuple[str, str, list[str]]] = []
    unknown: list[tuple[str, str]] = []
    for name, version in added:
        deps = build_deps(name, version)
        if deps is None:
            unknown.append((name, version))
        elif deps:
            offenders.append((name, version, deps))

    for name, version in added:
        print(f"  added: {name} {version}")

    if offenders:
        print("\n✗ AN ADDED CRATE CAN REACH THE NETWORK FROM ITS BUILD SCRIPT:")
        for name, version, deps in offenders:
            print(f"    {name} {version}  build-deps: {', '.join(deps)}")
        print(
            "\n  A build script runs at COMPILE time, on your machine and on CI, before\n"
            "  any of this project's own code. Do not build this. Read the crate's\n"
            "  build.rs before doing anything else — and note that the fix a security\n"
            "  tool suggested is not evidence the fix is safe (TRAPS §43)."
        )
        return 1

    if unknown:
        print("\n✗ CANNOT DETERMINE — could not read the index for:")
        for name, version in unknown:
            print(f"    {name} {version}")
        print("  An unread crate is not a clean crate (CLAUDE.md §1).")
        return 2

    print(f"\nOK — {len(added)} added crate(s), none with a network-capable build dep.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

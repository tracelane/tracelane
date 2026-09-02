#!/usr/bin/env python3
"""No crate in our dependency graph may have a NETWORK CLIENT in its build script.

WHY THIS EXISTS — 2026-08-20, and it is a real attack we walked into, not a
precaution.

`cargo deny` failed with "detected yanked crate (try `cargo update -p arrayref`)".
Following that advice resolved `arrayref` 0.3.10, whose only non-dev dependency
was `proc-macro1` — a typosquat of `proc-macro2` whose `build.rs`:

  * took `ureq` + `rustls` + `base64` as BUILD dependencies,
  * installed a `ServerCertVerifier` returning Ok() unconditionally, disabling
    TLS validation entirely,
  * downloaded a binary, wrote `/tmp/rust-setup`, `chmod +x`, and spawned it
    with stdio nulled (plus a `wscript.exe` branch for Windows),
  * hid its URLs as split base64 constants — decoded, payload
    `https://23.254.165.112:9089/` and C2 `23.254.165.112:443`,
  * and wrapped itself in authentic upstream code so it compiled correctly and
    read as legitimate.

THE PRECISE SHAPE, because the imprecise version defeats a reviewer. This block
used to say "copied the real proc-macro2 build.rs verbatim from line 212 on".
That is REFUTED: the nine-line trigger sits at 216-224, INSIDE `main()`, between
two blocks of genuine upstream code. The malicious region is 14-186 PLUS 216-224.
Anyone told "212+ is upstream" reads straight past the call site.

A build script runs at COMPILE time, on the developer's machine and on CI, before
any of the project's own code. Network access there is the whole ballgame.

WHY `cargo tree -e build` IS THE WRONG TOOL, recorded because it was the first
thing tried and it went GREEN on the poisoned lockfile: it only follows build
edges from the workspace root. The malware sat at normal -> normal -> build
(gateway -> blake3 -> arrayref -> build-dep), which that command cannot see.
`cargo metadata` walks EVERY package in the resolved graph, which is why this
guard uses it. A sweep that cannot see the known-bad case proves nothing
(CLAUDE.md §1).

USAGE
  check-build-script-network-deps.py            # scan the resolved graph
  check-build-script-network-deps.py --selftest # prove it BLOCKS
EXIT 0 clean · 1 a build script can reach the network · 2 could not determine
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

# Crates that give a build script the ability to open a socket, terminate TLS,
# or encode a payload for exfiltration. `base64` alone is weak evidence, but in
# a BUILD dependency alongside an HTTP client it is the shape of the real thing.
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
# Flagged only when it appears next to something above.
CORROBORATING = {"base64", "hex", "flate2"}

# Legitimate, reviewed exceptions. EMPTY ON PURPOSE — add an entry only with the
# reason in writing, and prefer removing the dependency.
ALLOW: dict[str, str] = {}


def offenders(meta: dict) -> list[tuple[str, str, list[str]]]:
    out = []
    for pkg in meta.get("packages", []):
        build = [
            d["name"] for d in pkg.get("dependencies", []) if d.get("kind") == "build"
        ]
        net = sorted(set(build) & NETWORK_CAPABLE)
        if not net:
            continue
        if pkg["name"] in ALLOW:
            continue
        extra = sorted(set(build) & CORROBORATING)
        out.append((pkg["name"], pkg["version"], net + extra))
    return sorted(out)


def load_metadata() -> dict:
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        # CANNOT DETERMINE is not a pass.
        print("✗ `cargo metadata` failed — the graph could NOT be read.")
        print(proc.stderr.strip()[:600])
        raise SystemExit(2)
    return json.loads(proc.stdout)


def selftest() -> int:
    # The real attack shape, taken verbatim from the incident.
    poisoned = {
        "packages": [
            {"name": "serde", "version": "1.0.0", "dependencies": []},
            {
                "name": "proc-macro1",
                "version": "1.0.107",
                "dependencies": [
                    {"name": "base64", "kind": "build"},
                    {"name": "rustls", "kind": "build"},
                    {"name": "ureq", "kind": "build"},
                    {"name": "unicode-ident", "kind": None},
                ],
            },
        ]
    }
    bad = offenders(poisoned)
    if not bad:
        print("SELFTEST FAILED — the real proc-macro1 shape was NOT caught")
        return 1
    if bad[0][0] != "proc-macro1":
        print(f"SELFTEST FAILED — caught the wrong package: {bad}")
        return 1

    # A normal build dependency must NOT trip it, or the guard gets switched off.
    clean = {
        "packages": [
            {
                "name": "tonic-build",
                "version": "0.12.0",
                "dependencies": [
                    {"name": "prost-build", "kind": "build"},
                    {"name": "reqwest", "kind": "dev"},
                    {"name": "hyper", "kind": None},
                ],
            }
        ]
    }
    if offenders(clean):
        print(
            "SELFTEST FAILED — flagged a clean package (dev/normal deps are not build deps)"
        )
        return 1

    # ── R77: the SECOND control B-263 left behind, falsified against a fixture ──
    #
    # `deny.toml` bans `proc-macro1` outright. That ban's only recorded proof was a
    # run against the REAL poisoned Cargo.lock kept from the incident — and that
    # lockfile is now gone from the tree, from ~/tracelane-security-evidence/, from
    # `git stash` and from every branch. The proof rested on a commit message.
    # A guard whose falsification cannot be re-run is a guard trusted on memory
    # (CLAUDE.md §1), so the shape is reconstructed as a committed fixture.
    #
    # It is checked HERE rather than in a new guard file because the two controls
    # are one lesson and the repo's rule is no new guards without a reason.
    deny_rc = _falsify_deny_ban()
    if deny_rc == 1:
        return 1

    # THE BANNER MUST NOT CLAIM WHAT DID NOT RUN. B-324, 2026-09-01: this printed
    # "the ban was OBSERVED BLOCKING on the fixture" unconditionally — including on
    # every run where `_falsify_deny_ban` had just SKIPPED for want of cargo-deny and
    # said so two lines above. A summary asserting a stronger verdict than the thing
    # it summarises is the defect this whole file exists to prevent, printed by the
    # file itself. `2` is the skip, and it gets its own honest sentence.
    if deny_rc == 2:
        print(
            "SELFTEST PASSED (PARTIAL) — the real proc-macro1 build-dep shape is\n"
            "  CAUGHT, and a package whose network crates are dev/normal (not build)\n"
            "  is NOT flagged. deny.toml's ban was NOT falsified on this run: see the\n"
            "  SKIP above. This run does NOT prove the ban blocks."
        )
        return 0

    print(
        "SELFTEST PASSED — the real proc-macro1 build-dep shape is CAUGHT, a\n"
        "  package whose network crates are dev/normal (not build) is NOT flagged,\n"
        "  and deny.toml's proc-macro1 ban was OBSERVED BLOCKING on the fixture."
    )
    return 0


def _falsify_deny_ban() -> int:
    """Prove `deny.toml`'s `proc-macro1` ban BLOCKS, against a committed fixture.

    Returns 0 on a proven block, 1 on a proven non-block, and 2 when cargo-deny is
    absent — an ABSENT TOOL IS NOT A PASS. The 2 is load-bearing: the caller uses it
    to print a PARTIAL banner, because a distinct skip line under a banner that still
    claims the ban was observed blocking is not honesty, it is a footnote under a
    false headline.
    """
    fixture = pathlib.Path(__file__).parent / "fixtures" / "b263-deny-ban"
    if not (fixture / "Cargo.toml").is_file():
        print(f"SELFTEST FAILED — the B-263 fixture is missing at {fixture}")
        return 1

    # THE FIXTURE'S `Cargo.lock` MUST NOT BE TRACKED, AND THIS IS WHERE THAT IS
    # ENFORCED — beside the thing it constrains, not in a note somewhere.
    #
    # Earned 2026-08-27. Grype and OSV-Scanner catalog Rust packages FROM LOCKFILES.
    # A committed `Cargo.lock` here therefore advertised the deliberately-planted
    # `proc-macro1 1.0.107` to both of them as a live dependency, and the public
    # repo's Security Scan went red on a TEST FIXTURE — two jobs, every night. That
    # is worse than a missed finding: a scanner that is permanently red for a reason
    # everyone knows is a scanner nobody reads.
    #
    # The repair is deliberately NOT a suppression. Ignoring `proc-macro1` by name,
    # or ignoring MAL-2026-14338 / RUSTSEC-2026-0265 by id, would have silenced the
    # scanners for the REAL crate too — the one whose `build.rs` downloads and
    # executes a binary with TLS verification off. Not committing the lockfile costs
    # the scanners nothing: `cargo deny` regenerates it from the path dependency at
    # selftest time (verified — this function still observes the ban BLOCKING with no
    # lockfile present), and the ban in `deny.toml` is unchanged.
    lock = fixture / "Cargo.lock"
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(lock)],
        capture_output=True,
        text=True,
        check=False,
    )
    if tracked.returncode == 0:
        print(
            "SELFTEST FAILED — the B-263 fixture's Cargo.lock is TRACKED IN GIT.\n"
            "  Grype and OSV-Scanner read Rust packages out of lockfiles, so a\n"
            "  committed one re-publishes the planted `proc-macro1 1.0.107` to every\n"
            "  vulnerability scanner as a live Critical and turns the public repo's\n"
            "  Security Scan permanently red on a test fixture.\n"
            "  Fix: `git rm --cached` it. `cargo deny` regenerates it on demand and\n"
            "  .gitignore already lists it. Do NOT suppress the advisory instead —\n"
            "  that would silence the scanners for the real crate too."
        )
        return 1
    # `cargo deny` IS `cargo-deny`: cargo resolves a subcommand by looking for a
    # `cargo-<name>` binary on PATH, so cargo-deny's absence is decided by that ONE
    # binary. `cargo` being present says nothing about it.
    #
    # This condition read `... is None and shutil.which("cargo") is None` — skip only
    # when BOTH are missing — which is wrong in the one configuration that matters and
    # was invisible for as long as the two were absent together. B-324, 2026-09-01: the
    # nightly gate's runner had neither, so it skipped correctly; the moment cargo went
    # on its PATH the selftest fell through to `cargo deny`, got
    # `error: no such command: 'deny'`, and reported
    # "cargo-deny exited non-zero, but not with error[banned]" — a MISSING TOOL
    # reported as a FAILED PROOF. That is the §14 error inside a guard whose whole
    # subject is not mistaking one state for another, and it was the last thing
    # standing between the nightly full gate and its first green.
    if shutil.which("cargo-deny") is None:
        print(
            "  SKIP  deny.toml ban not falsified — cargo-deny is not installed"
            " (`cargo deny` needs the cargo-deny binary on PATH). NOT a pass."
        )
        return 2

    proc = subprocess.run(
        [
            "cargo",
            "deny",
            "--manifest-path",
            str(fixture / "Cargo.toml"),
            "check",
            "--config",
            str(pathlib.Path(__file__).parents[2] / "deny.toml"),
            "bans",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    blob = proc.stdout + proc.stderr
    if proc.returncode == 0:
        print(
            "SELFTEST FAILED — deny.toml did NOT block a lockfile naming proc-macro1.\n"
            "  The ban is present in the file and not load-bearing, which is the\n"
            "  worst state: it reads as a control and is not one."
        )
        return 1
    # MATCH THE DIAGNOSTIC AND THE CRATE, NOT THE WORD.
    #
    # The first version of this asserted `"banned" in blob` while the fixture lived
    # in a directory called `b263-banned-crate` — so the PATH in cargo-deny's error
    # message satisfied the assertion, and the check went green while cargo-deny was
    # actually failing to PARSE the manifest and never evaluating the ban at all.
    # A probe whose own fixture name can satisfy it is measuring nothing. Caught by
    # a negative control (rename the crate; the check must go red), which is the
    # only thing that could have caught it.
    if "error[banned]" not in blob or "proc-macro1" not in blob:
        print(
            "SELFTEST FAILED — cargo-deny exited non-zero, but not with\n"
            "  `error[banned]` naming proc-macro1. Non-zero for some OTHER reason\n"
            "  (a parse error, a missing config) is not the proof we wanted:\n"
            + "\n".join(blob.splitlines()[-8:])
        )
        return 1
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print(__doc__)
        return 2

    meta = load_metadata()
    bad = offenders(meta)
    n = len(meta.get("packages", []))
    if bad:
        print("✗ BUILD SCRIPT CAN REACH THE NETWORK:")
        for name, ver, deps in bad:
            print(f"    {name} {ver}  build-deps: {', '.join(deps)}")
        print(
            "\n  A build script runs at COMPILE time, on your machine and on CI,\n"
            "  before any of this project's code. An HTTP client there is how\n"
            "  `proc-macro1` shipped an RCE dropper through `arrayref` (B-263).\n"
            "  Read the crate's build.rs before doing anything else. Do NOT add it\n"
            "  to ALLOW to make this pass."
        )
        return 1
    print(
        f"OK — {n} packages in the resolved graph, none with a network-capable build script."
    )
    print(
        "  LIMIT, stated: this checks DECLARED build-dependencies. A build script\n"
        "  that shells out to `curl`, or vendors its own socket code, declares\n"
        "  nothing and is invisible here. That half is review."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

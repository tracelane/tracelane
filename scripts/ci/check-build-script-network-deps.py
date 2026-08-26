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
    if deny_rc != 0:
        return deny_rc

    print(
        "SELFTEST PASSED — the real proc-macro1 build-dep shape is CAUGHT, a\n"
        "  package whose network crates are dev/normal (not build) is NOT flagged,\n"
        "  and deny.toml's proc-macro1 ban was OBSERVED BLOCKING on the fixture."
    )
    return 0


def _falsify_deny_ban() -> int:
    """Prove `deny.toml`'s `proc-macro1` ban BLOCKS, against a committed fixture.

    Returns 0 on a proven block, 1 on a proven non-block, and 0 with a loud SKIP
    when cargo-deny is absent — an ABSENT TOOL IS NOT A PASS, so it says so on its
    own line rather than folding into the PASSED banner above.
    """
    fixture = pathlib.Path(__file__).parent / "fixtures" / "b263-deny-ban"
    if not (fixture / "Cargo.toml").is_file():
        print(f"SELFTEST FAILED — the B-263 fixture is missing at {fixture}")
        return 1
    if shutil.which("cargo-deny") is None and shutil.which("cargo") is None:
        print(
            "  SKIP  deny.toml ban not falsified — cargo-deny unavailable. NOT a pass."
        )
        return 0

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

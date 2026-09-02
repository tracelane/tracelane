#!/usr/bin/env python3
"""Hot-path cache TTLs must survive the gap between a sparse tenant's requests.

WHY THIS EXISTS (B-256). Four caches sit on the gateway's chat hot path. THREE of
them shipped with a TTL shorter than the interval between production requests
(~400s), so they never hit, and every request paid the cold path they existed to
avoid. Measured on prod 2026-08-18, one request:

    auth (60s TTL)            169.9 ms
    BYOK key (300s TTL)        17.5 ms
    capability registry (30s)  14.1 ms
    everything else             0.8 ms
    -------------------------------------
    total                     202.3 ms   <- against 1.7ms once all four are warm

The same mistake, three times, in three modules, over months. The fourth cache
had already been cured of it -- `entitlement_cache` was 30s once and its comment
records the fix -- and the registry loader's doc says it "mirrors
entitlement_cache" while carrying the pre-fix number. Prose did not stop this.

THE RULE. A hot-path cache TTL below FLOOR_SECS must carry an explicit written
exemption on an adjacent line:

    // hot-path-cache-ttl: exempt -- <why this one is safe>

The auth cache is the worked example: 60s is deliberate there, because a
background warm-refresh keeps entries alive and makes the SHORT ttl a tighter
revocation bound rather than a latency cost. That is a real reason and it is
written down. "It felt safer" is not, and has to be typed out to pass.

HONEST LIMIT, stated because a guard that oversells itself is worse than none:
this checks the DECLARED constant. It cannot know a deployment's real traffic
interval, and it cannot prove an exemption's reasoning is sound -- only that
somebody had to write one. It also only looks at the files listed in SITES; a
cache added in a new module is invisible to it until that module is added here.
"""

import pathlib
import re
import sys

# 600s, RAISED FROM 300s ON 2026-08-20 — the old floor was BELOW the interval it
# existed to protect against, which made it a threshold that could not fire.
#
# Measured on prod, 278 real requests over 2026-08-19/20 (synthetic bursts
# excluded): the gap between consecutive requests is **423s at p50 and 565s at
# p90**. The dogfood driver sleeps `300 + RANDOM%300`, i.e. 5-10 minutes, so
# that is structural rather than a quiet afternoon.
#
# With FLOOR_SECS = 300 a cache could declare exactly 300s, pass this guard, and
# still be expired every single time a request arrived. That is precisely what
# happened: GWY-24's `no_embedder` negative cache shipped at 300s, passed here,
# and never once hit — every miss re-walked the provider list into Postgres on
# the request path and cost **p50 1.78ms -> 18.45ms (~10x)** on the dominant
# prod model. B-256's own lesson, reintroduced by the feature and waved through
# by the guard written for it.
#
# 600s clears the measured p90 gap. It is a FLOOR, not a target: if traffic ever
# gets sparser than this, re-measure and raise it again rather than exempting
# the site.
FLOOR_SECS = 600

# (path, const-name regex). Kept explicit rather than globbed: a wrong file list
# is visible here, whereas a clever glob that silently matches nothing is not.
SITES = [
    ("crates/gateway/src/db/api_keys.rs", r"DEFAULT_AUTH_CACHE_TTL_SECS"),
    ("crates/gateway/src/db/provider_keys.rs", r"KEY_CACHE_TTL"),
    ("crates/gateway/src/guardrail/registry_loader.rs", r"TTL"),
    ("crates/gateway/src/entitlement_cache.rs", r"TTL"),
    # Added 2026-08-20. GWY-24's negative cache lived here at 300s against a
    # measured 423s p50 request gap and this guard never saw it — the file was
    # not listed AND the value was an inline Duration inside a builder chain
    # rather than a named const, so listing alone would have matched nothing and
    # reported success. Both halves are fixed: the site is listed, and the value
    # is now `NO_EMBEDDER_TTL_SECS`. The zero-match check below is what makes
    # the second half impossible to get wrong again.
    ("crates/gateway/src/semantic_cache.rs", r"NO_EMBEDDER_TTL_SECS"),
    # Added 2026-08-27 with the cache itself (EVL-28 item 11). The online-eval
    # POLICY cache is read on the admission path of every chat request, so it is
    # a hot-path cache by the definition this guard uses. Listed in the SAME
    # change that introduces it, and its value is a named const for the reason
    # the 2026-08-20 note above records: listing a file whose TTL is an inline
    # Duration matches nothing and reports success.
    ("crates/gateway/src/online_eval.rs", r"POLICY_CACHE_TTL_SECS"),
]

EXEMPT = re.compile(r"hot-path-cache-ttl:\s*exempt\s*--\s*\S")
SECS = re.compile(r"Duration::from_secs\((\d[\d_]*)\)")
PLAIN = re.compile(r":\s*u64\s*=\s*(\d[\d_]*)\s*;")


def scan(root: pathlib.Path):
    findings = []
    checked = 0
    for rel, name_re in SITES:
        path = root / rel
        if not path.exists():
            findings.append((rel, 0, None, f"listed site does not exist: {rel}"))
            continue
        site_matches = 0
        lines = path.read_text(encoding="utf-8").splitlines()
        pat = re.compile(rf"const\s+{name_re}\b")
        for i, line in enumerate(lines):
            if not pat.search(line):
                continue
            m = SECS.search(line) or PLAIN.search(line)
            if not m:
                continue
            checked += 1
            site_matches += 1
            secs = int(m.group(1).replace("_", ""))
            if secs >= FLOOR_SECS:
                continue
            # Look back over the const's doc/comment block for an exemption.
            j, exempt = i - 1, False
            while j >= 0 and (
                lines[j].lstrip().startswith("//") or lines[j].strip() == ""
            ):
                if EXEMPT.search(lines[j]):
                    exempt = True
                    break
                j -= 1
            if not exempt:
                findings.append(
                    (
                        rel,
                        i + 1,
                        secs,
                        f"{secs}s is below the {FLOOR_SECS}s floor with no written exemption",
                    )
                )
        # A LISTED SITE THAT MATCHES NOTHING IS A FAILURE, NOT A PASS.
        #
        # Without this, adding a file with a slightly wrong const regex checks
        # zero TTLs and still prints OK — the guard reports success for a site
        # it never read. That is exactly how GWY-24's 300s negative cache went
        # unseen: the value was an inline `Duration::from_secs(300)` in a
        # builder chain, so no `const` pattern could ever have matched it, and
        # nothing said so. `CANNOT DETERMINE` is not a pass (CLAUDE.md §1).
        if site_matches == 0:
            findings.append(
                (
                    rel,
                    0,
                    None,
                    (
                        f"listed site matched NO TTL const for /{name_re}/ — the "
                        f"guard read nothing here. Either the regex is wrong or "
                        f"the TTL is not a named const (an inline Duration is "
                        f"invisible to it)."
                    ),
                )
            )
    return findings, checked


def selftest(root: pathlib.Path) -> int:
    """Plant a violation and prove it BLOCKS; then prove the exemption clears it.

    Both halves matter. A guard that only proves it passes on the real tree is
    proving nothing -- it would pass identically if it checked nothing at all.
    """
    import shutil
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        for rel, _ in SITES:
            src = root / rel
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dst) if src.exists() else dst.write_text("")

        target = tmp / "crates/gateway/src/guardrail/registry_loader.rs"
        body = target.read_text()

        # 1. A short TTL with no exemption must FAIL.
        planted = re.sub(
            r"const MAX_CAPACITY",
            "const TTL: Duration = Duration::from_secs(30);\nconst MAX_CAPACITY",
            body,
            count=1,
        )
        target.write_text(planted)
        f, _ = scan(tmp)
        if any(x[0].endswith("registry_loader.rs") for x in f):
            print("  ok: a 30s TTL with no exemption is BLOCKED")
        else:
            print("  FAIL: a 30s TTL with no exemption was allowed through")
            ok = False

        # 2. The same TTL WITH an exemption must PASS -- otherwise the guard is
        #    unusable and the next person deletes it rather than argue with it.
        planted2 = re.sub(
            r"const MAX_CAPACITY",
            "// hot-path-cache-ttl: exempt -- planted by selftest\n"
            "const TTL: Duration = Duration::from_secs(30);\nconst MAX_CAPACITY",
            body,
            count=1,
        )
        target.write_text(planted2)
        f2, _ = scan(tmp)
        if any(x[0].endswith("registry_loader.rs") for x in f2):
            print("  FAIL: a written exemption did not clear the finding")
            ok = False
        else:
            print("  ok: a written exemption clears it")

    print("SELFTEST PASSED" if ok else "SELFTEST FAILED")
    return 0 if ok else 1


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    # REJECT UNKNOWN ARGUMENTS. The meta-gate caught this script accepting
    # `--tracelane-meta-gate-nonsense-flag` and exiting 0, and it was right to:
    # a script that ignores argv might be ignoring `--selftest` too, in which
    # case the selftest "passing" would prove nothing at all. Parsing strictly is
    # what makes the selftest's exit code mean something.
    for arg in sys.argv[1:]:
        if arg != "--selftest":
            print(f"unknown argument: {arg}\nusage: {sys.argv[0]} [--selftest]")
            return 2
    if "--selftest" in sys.argv:
        return selftest(root)
    findings, checked = scan(root)
    if findings:
        print("HOT-PATH CACHE TTL below the floor:")
        for rel, line, _secs, msg in findings:
            print(f"  {rel}:{line}: {msg}")
        print(
            "\nA cache whose TTL is shorter than the gap between requests is not a\n"
            "cache, it is a tax: every request finds an expired entry and pays the\n"
            "cold path. Raise it, or write the exemption:\n"
            "    // hot-path-cache-ttl: exempt -- <why this one is safe>"
        )
        return 1
    print(
        f"hot-path cache TTLs: {checked} checked, all >= {FLOOR_SECS}s or explicitly exempt."
    )
    print(
        "HONEST LIMIT: this reads the DECLARED constant. It cannot know the real\n"
        "traffic interval, cannot judge whether an exemption's reasoning is sound,\n"
        "and only sees the files listed in SITES."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

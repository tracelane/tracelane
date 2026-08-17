#!/usr/bin/env python3
"""check-external-links.py — guard the class of bug where a user-facing external
link points at the WRONG target (or a dead one).

Origin: the Rekor v1-vs-v2 logIndex bug (2026-07-13). The audit page linked
`search.sigstore.dev`, which searches the LEGACY Rekor v1 log. v1 and v2
(`log2025-1`) have INDEPENDENT logIndex spaces, so our v2 index resolved a
stranger's unrelated 2023 v1 entry. Every in-app test passed because they checked
that the link *rendered*, never what it *resolved to*. This closes that boundary.

Two layers, with a deliberate risk balance:

  STATIC (offline, deterministic -> HARD FAIL): banned hosts must not be LINKED
    (`https://<host>`) from a surface where they would be wrong. `search.sigstore.dev`
    must NEVER be linked from the web app. This is about OUR code, so it blocks — no
    network. (Prose mentions in comments are fine; only the `https://<host>` link
    form is banned.)

  LIVE (network): resolve each hardcoded user-facing external URL, and for
    IDENTITY-claiming endpoints verify the returned bytes carry OUR fingerprint
    (the checkpoint's origin line == our pinned log). An identity MISMATCH is a
    HARD FAIL (that IS the bug class). A dead link (4xx/5xx) is a loud WARN. An
    unreachable host is a WARN — we do NOT block our own deploy on a third party's
    uptime (avoid unnecessary risk). Network failures never turn into false fails.

Modes:
  --static   offline static guards only (used by verify-all --fast + CI merge gate)
  --selftest offline: plants a banned link, proves the static guard reports it,
             and proves a correct link is NOT reported
  (default)  static + live (used as a pre-deploy step in scripts/deploy/web.sh)

Flags are parsed by argparse, so an unrecognised argument EXITS NON-ZERO. That
is not cosmetic: this used to be `"--static" in sys.argv`, under which
`--selftest` (and every typo of `--static`) silently fell through to the LIVE
network path — the slow, third-party-dependent mode — while the caller believed
it had asked for something else.

The GROUND-TRUTH MANIFEST is the three tables below — the single source of truth
for "which external target is correct". Update those, not scattered strings.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# ── Ground-truth manifest ────────────────────────────────────────────────────
# Hosts that must NEVER be LINKED (https://<host>) from the web surface, + why.
BANNED_HOSTS: dict[str, str] = {
    "search.sigstore.dev": (
        "Rekor v1 search UI — the WRONG log for our anchors. Our anchors are in "
        "Rekor v2 (log2025-1), whose logIndex space is INDEPENDENT of v1, so a v2 "
        "index resolves a stranger's v1 entry. Rekor v2 has no per-entry web page; "
        "link the signed checkpoint and verify offline from the exported evidence."
    ),
}

# Endpoints whose returned bytes must prove OUR identity (not just resolve 2xx).
IDENTITY_CHECKS: list[dict[str, str]] = [
    {
        "url": "https://log2025-1.rekor.sigstore.dev/checkpoint",
        "must_contain": "log2025-1.rekor.sigstore.dev",
        "why": (
            "the signed checkpoint's origin line MUST be our pinned Rekor v2 log "
            "(log2025-1); a different origin means the anchor UI points at the "
            "wrong log — the exact v1/v2 bug class"
        ),
    },
]

# Hosts to skip in the LIVENESS pass — API/base endpoints (not browsable pages;
# their paths 401/404 by design) and example/placeholder hosts. These are server
# call targets or docs examples, not user-facing links, so a non-200 is noise, not
# a broken link. (The banned-host STATIC guard still applies to all of them.)
API_HOSTS = {
    "gateway.tracelane.dev",
    "api.tracelane.dev",
    "api.workos.com",
    "admin.workos.com",
    "hooks.slack.com",
    "discord.com",
    "polar.sh",
    "example.com",
    "example.org",
    "app.example",
    "gateway.example",
}

# Directories that render to the USER (exclude tests/mocks/e2e — those carry
# intentional placeholder URLs like gateway.example / a stale vercel.app).
WEB_SURFACE = ["apps/web/components", "apps/web/app", "apps/web/lib", "apps/site/src"]
TEST_MARKERS = (".test.", ".spec.", "__mocks__", "/e2e/", "/fixtures/")

# A well-formed absolute URL with a dotted host; anything with a template
# placeholder (`$`, `{`) is a fragment, not a real link.
URL_RE = re.compile(
    r"https?://[a-z0-9][a-z0-9.-]*\.[a-z]{2,}[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]*"
)


def git_files(dirs: list[str]) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", *dirs], capture_output=True, text=True, check=False
    ).stdout.splitlines()
    return [f for f in out if not any(m in f for m in TEST_MARKERS)]


def static_check(files: list[str] | None = None) -> list[str]:
    """Banned hosts LINKED (https://<host>) anywhere on the web surface -> errors.

    `files` overrides the scanned set (used only by --selftest, which plants
    fixtures in a temp dir). None = the real web surface, as CI runs it.
    """
    errors: list[str] = []
    patterns = {
        host: re.compile(r"https?://" + re.escape(host)) for host in BANNED_HOSTS
    }
    for f in git_files(WEB_SURFACE) if files is None else files:
        try:
            with open(f, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for host, pat in patterns.items():
                if pat.search(line):
                    errors.append(
                        f"{f}:{i} LINKS banned host `{host}` — {BANNED_HOSTS[host]}"
                    )
    return errors


def http_get(url: str, timeout: int = 10) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "tracelane-link-check"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(65536).decode("utf-8", "replace")


def fetch(url: str, tries: int = 3) -> tuple[tuple[int, str] | None, Exception | None]:
    last: Exception | None = None
    for _ in range(tries):
        try:
            return http_get(url), None
        except urllib.error.HTTPError as e:  # a real HTTP status (4xx/5xx)
            return (e.code, ""), None
        except Exception as e:  # noqa: BLE001 — network/DNS/timeout = unreachable
            last = e
    return None, last


def live_check() -> tuple[list[str], list[str]]:
    """(hard_errors, warnings). Identity mismatch = error; dead/unreachable = warn."""
    errors: list[str] = []
    warns: list[str] = []

    for chk in IDENTITY_CHECKS:
        res, err = fetch(chk["url"])
        if res is None:
            warns.append(
                f"IDENTITY {chk['url']} unreachable ({err}); skipped — third-party "
                "uptime is not our deploy gate"
            )
            continue
        status, body = res
        if status != 200:
            warns.append(
                f"IDENTITY {chk['url']} -> HTTP {status} (dead?); {chk['why']}"
            )
        elif chk["must_contain"] not in body:
            errors.append(
                f"IDENTITY MISMATCH {chk['url']} does NOT contain "
                f"`{chk['must_contain']}` — {chk['why']}. First bytes: {body[:80]!r}"
            )
        else:
            print(f"  ✓ identity {chk['url']} carries `{chk['must_contain']}`")

    seen: set[str] = set()
    for f in git_files(WEB_SURFACE):
        try:
            with open(f, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(".,)}\"'`>")
            host = url.split("://", 1)[1].split("/", 1)[0]
            if url in seen or host in API_HOSTS or "$" in url or "{" in url:
                continue
            seen.add(url)
            res, err = fetch(url, tries=2)
            if res is None:
                warns.append(f"LIVENESS {url} unreachable ({err}) — verify manually")
            elif res[0] >= 400:
                warns.append(f"LIVENESS {url} -> HTTP {res[0]} (broken link?)")
    return errors, warns


def selftest() -> int:
    """Plant a banned link, prove the STATIC guard reports it, prove clean passes.

    OFFLINE BY CONSTRUCTION, and that is asserted rather than asserted-about:
    `urllib.request.urlopen` is replaced with a tripwire for the duration, and
    the last case fails if anything tripped it. The live layer cannot be
    selftested honestly — it resolves third-party endpoints and deliberately
    WARNS (never fails) on their downtime, so an offline assertion about it
    would be theatre. Only the hard-failing static layer is proven here.
    """
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if cond:
            print(f"  ✓ {name}")
        else:
            print(f"  ✗ {name}{f' — {detail}' if detail else ''}")
            failures.append(name)

    before = subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True, check=False
    ).stdout

    tripped: list[str] = []
    real_urlopen = urllib.request.urlopen

    def _tripwire(*a, **kw):
        tripped.append(str(a[:1]))
        raise AssertionError("selftest must not touch the network")

    urllib.request.urlopen = _tripwire  # type: ignore[assignment]
    try:
        # The manifest IS the guard. An empty one would make every case below
        # pass while nothing is actually banned.
        check("manifest_is_not_empty", bool(BANNED_HOSTS), "BANNED_HOSTS is empty")
        host = next(iter(BANNED_HOSTS))

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)

            linked = tmp / "AnchorLink.tsx"
            linked.write_text(
                "export function AnchorLink() {\n"
                f'  return <a href="https://{host}/?logIndex={{i}}">view</a>;\n'
                "}\n",
                encoding="utf-8",
            )
            errs = static_check([str(linked)])
            check(
                "banned_host_LINKED_blocks",
                any(host in e for e in errs),
                f"planted https://{host} link went unreported: {errs}",
            )
            check(
                "violation_reports_file_and_line",
                any(f"{linked}:2" in e for e in errs),
                f"expected '{linked}:2' in {errs}",
            )

            # http:// is the same defect wearing a different scheme.
            plain = tmp / "Plain.tsx"
            plain.write_text(f'const u = "http://{host}/entry";\n', encoding="utf-8")
            check(
                "banned_host_http_scheme_blocks",
                bool(static_check([str(plain)])),
                "http:// form was not caught",
            )

            # Documented negative: a PROSE mention (no scheme) is explicitly
            # allowed. Without this the guard could ban the word and still look
            # right — and the code comments that explain the v1/v2 trap would
            # become unwritable.
            prose = tmp / "Note.tsx"
            prose.write_text(
                f"// NOTE: {host} is the Rekor v1 UI — the WRONG log for our anchors.\n",
                encoding="utf-8",
            )
            check(
                "prose_mention_does_not_block",
                not static_check([str(prose)]),
                "a scheme-less prose mention was flagged",
            )

            # The correct target must pass, or the guard blocks the fix.
            good = tmp / "Good.tsx"
            good.write_text(
                'const CHECKPOINT = "https://log2025-1.rekor.sigstore.dev/checkpoint";\n',
                encoding="utf-8",
            )
            check(
                "correct_rekor_v2_link_passes",
                not static_check([str(good)]),
                "the pinned Rekor v2 checkpoint URL was flagged",
            )

            # Mixed tree: one clean file does not launder the offender.
            mixed = static_check([str(good), str(linked), str(prose)])
            check(
                "offender_beside_clean_files_blocks",
                len(mixed) == 1 and host in mixed[0],
                f"expected exactly one error naming {host}, got {mixed}",
            )
    finally:
        urllib.request.urlopen = real_urlopen  # type: ignore[assignment]

    check("no_network_touched", not tripped, f"urlopen called with {tripped}")

    after = subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True, check=False
    ).stdout
    check("tree_restored", before == after, "selftest changed the working tree")

    if failures:
        print(f"selftest FAILED — {len(failures)} case(s): {', '.join(failures)}")
        return 1
    print("selftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Guard user-facing external links against wrong/dead targets."
    )
    ap.add_argument(
        "--static",
        action="store_true",
        help="offline banned-link guard only (no network)",
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="offline: plant a banned link and prove this guard blocks it",
    )
    args = ap.parse_args()  # unknown flags -> usage on stderr, exit 2

    if args.selftest:
        return selftest()

    static_only = args.static
    print("== external-link + identity guard ==")

    errors = static_check()
    warns: list[str] = []
    if not static_only:
        live_err, warns = live_check()
        errors += live_err
    else:
        print("  (--static: offline banned-link guard only; skipping network checks)")

    for w in warns:
        print(f"  ⚠️  {w}")
    if errors:
        print("\n❌ external-link guard FAILED:")
        for e in errors:
            print(f"   - {e}")
        return 1
    print(
        f"✓ external-link guard OK ({'static only' if static_only else 'static + live'}"
        f"{f'; {len(warns)} non-blocking warning(s)' if warns else ''})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

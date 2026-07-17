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
  (default)  static + live (used as a pre-deploy step in scripts/deploy/web.sh)

The GROUND-TRUTH MANIFEST is the three tables below — the single source of truth
for "which external target is correct". Update those, not scattered strings.
"""

from __future__ import annotations

import re
import subprocess
import sys
import urllib.error
import urllib.request

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
WEB_SURFACE = ["apps/web/components", "apps/web/app", "apps/web/lib"]
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


def static_check() -> list[str]:
    """Banned hosts LINKED (https://<host>) anywhere on the web surface -> errors."""
    errors: list[str] = []
    patterns = {
        host: re.compile(r"https?://" + re.escape(host)) for host in BANNED_HOSTS
    }
    for f in git_files(WEB_SURFACE):
        try:
            lines = open(f, encoding="utf-8").read().splitlines()
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
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — fixed hosts
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
            text = open(f, encoding="utf-8").read()
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


def main() -> int:
    static_only = "--static" in sys.argv
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

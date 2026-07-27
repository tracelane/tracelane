#!/usr/bin/env python3
"""CI guard: no silent localhost gateway fallback in apps/web server code.

The failure this catches (the checkout CSP / gateway-URL incident): a server
route that reads `process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080"`
will, when that env var is unset on the Cloudflare Worker, fetch localhost — and
Cloudflare blocks the Worker subrequest with "error code: 1003" (Direct IP Access
Not Allowed). That silently breaks checkout AND every gateway read.

Fix: use the fail-loud resolver `gatewayBaseUrl()` from `apps/web/lib/gateway.ts`,
which THROWS in production when the URL is unset instead of pointing at localhost.

This guard bans the raw `?? "http(s)://localhost..."` gateway fallback everywhere
in apps/web except the one sanctioned resolver (which owns the dev-only fallback
behind a prod-throw) and non-shipping files (tests, e2e, playwright config).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "apps" / "web"
# Any `?? "http://localhost..."` (the silent-fallback landmine), single or double quotes.
PATTERN = re.compile(r"""\?\?\s*["']https?://localhost""")
# The ONE file allowed to name a localhost fallback — it gates it behind a prod throw.
ALLOW = {WEB / "lib" / "gateway.ts"}


def skip(p: Path) -> bool:
    s = str(p)
    return (
        p in ALLOW
        or "/.next/" in s
        or "/.open-next/" in s
        or "/node_modules/" in s
        or s.endswith(".test.ts")
        or "/e2e/" in s
        or "playwright.config" in s
    )


def main() -> int:
    hits = []
    for p in WEB.rglob("*.ts*"):
        if p.suffix not in (".ts", ".tsx") or skip(p):
            continue
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if PATTERN.search(line):
                hits.append(f"{p.relative_to(ROOT)}:{i}: {line.strip()}")

    if hits:
        print(
            "FAIL: silent localhost gateway fallback — use gatewayBaseUrl() (fail-loud):"
        )
        for h in hits:
            print(f"  {h}")
        print("  This guard blocks a silent localhost gateway fallback (Layer 2).")
        return 1
    print("OK: no silent localhost gateway fallback in apps/web")
    return 0


if __name__ == "__main__":
    sys.exit(main())

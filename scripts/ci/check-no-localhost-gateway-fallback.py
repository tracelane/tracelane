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

Exit codes:
    0 — clean
    1 — a silent localhost fallback was found (or --selftest failed)
    2 — bad usage (unrecognised argument)

Run locally:  python3 scripts/ci/check-no-localhost-gateway-fallback.py
Falsify it:   python3 scripts/ci/check-no-localhost-gateway-fallback.py --selftest

`--selftest` plants the fallback in a throwaway tree and asserts the guard
REPORTS it, asserts a clean tree PASSES, and asserts every exemption (the
sanctioned resolver, tests, e2e, playwright config, build output) still holds.
A guard whose blocking has never been observed is not a guard.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "apps" / "web"
# Any `?? "http://localhost..."` (the silent-fallback landmine), single or double quotes.
PATTERN = re.compile(r"""\?\?\s*["']https?://localhost""")
# The ONE path allowed to name a localhost fallback — it gates it behind a prod
# throw. Held relative to the scanned web root so the selftest can exercise the
# exemption against a throwaway tree rather than trusting it by inspection.
ALLOW_REL = frozenset({"lib/gateway.ts"})


def skip(path: Path, web_root: Path) -> bool:
    s = path.as_posix()
    try:
        rel = path.relative_to(web_root).as_posix()
    except ValueError:  # pragma: no cover — path always sits under web_root
        rel = s
    return (
        rel in ALLOW_REL
        or "/.next/" in s
        or "/.open-next/" in s
        or "/node_modules/" in s
        or s.endswith(".test.ts")
        or "/e2e/" in s
        or "playwright.config" in s
    )


def scan(web_root: Path, label_root: Path) -> list[str]:
    """Return `file:line: text` for every silent localhost fallback under web_root."""
    hits: list[str] = []
    for p in sorted(web_root.rglob("*.ts*")):
        if p.suffix not in (".ts", ".tsx") or skip(p, web_root):
            continue
        # errors="replace", not a skip: a file that fails to decode must still be
        # scanned, or hiding the landmine becomes as easy as a stray byte.
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if PATTERN.search(line):
                try:
                    label = p.relative_to(label_root).as_posix()
                except ValueError:
                    label = p.name
                hits.append(f"{label}:{i}: {line.strip()}")
    return hits


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

LANDMINE = (
    'const base = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8080";\n'
)

# (relative path under the fake web root, file contents, must_be_flagged)
SELFTEST_FILES: list[tuple[str, str, bool]] = [
    # --- must BLOCK -------------------------------------------------------
    ("app/api/checkout/route.ts", LANDMINE, True),
    (
        "app/billing/usage/page.tsx",
        "const base = env.NEXT_PUBLIC_GATEWAY_URL ?? 'https://localhost:8080';\n",
        True,
    ),
    (
        "lib/provider-keys.ts",
        'const base = process.env.GW ??   "http://localhost:3000";\n',
        True,
    ),
    # --- must PASS --------------------------------------------------------
    (
        "app/traces/page.tsx",
        "import { gatewayBaseUrl } from '@/lib/gateway';\nconst base = gatewayBaseUrl();\n",
        False,
    ),
    # The one sanctioned owner of the fallback: it may name it, because it
    # throws in production instead of returning it.
    ("lib/gateway.ts", LANDMINE, False),
    ("lib/gateway.test.ts", LANDMINE, False),
    ("e2e/checkout.spec.ts", LANDMINE, False),
    ("playwright.config.ts", LANDMINE, False),
    (".next/server/chunk.ts", LANDMINE, False),
    ("node_modules/pkg/index.ts", LANDMINE, False),
]


def _tree_state() -> str | None:
    """`git status --porcelain` for the real repo, or None if git is unusable."""
    try:
        r = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def selftest() -> int:
    failures = 0
    before = _tree_state()

    with tempfile.TemporaryDirectory() as td:
        web = Path(td) / "apps" / "web"
        for rel, body, _ in SELFTEST_FILES:
            p = web / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")

        hits = scan(web, Path(td))
        flagged = {h.split(":", 1)[0].removeprefix("apps/web/") for h in hits}

        for rel, _, must_flag in SELFTEST_FILES:
            got = rel in flagged
            ok = got == must_flag
            verb = "BLOCKS" if must_flag else "allows"
            print(
                f"  {'✓' if ok else '✗'} {verb} {rel}"
                f"{'' if ok else f'  (expected flagged={must_flag}, got {got})'}"
            )
            if not ok:
                failures += 1

        # Assert the negative at TREE level too: a tree with no landmine at all
        # must produce zero hits. Without this, a guard that fires on every file
        # would still satisfy the per-file cases above.
        clean = Path(td) / "clean" / "apps" / "web"
        (clean / "app").mkdir(parents=True)
        (clean / "app" / "page.tsx").write_text(
            "const base = gatewayBaseUrl();\n", encoding="utf-8"
        )
        clean_hits = scan(clean, Path(td) / "clean")
        if clean_hits:
            print(f"  ✗ clean tree PASSES — got {len(clean_hits)} false hit(s)")
            failures += 1
        else:
            print("  ✓ clean tree PASSES (guard does not fire on everything)")

    after = _tree_state()
    if before is None or after is None:
        print("  ! tree-unchanged check SKIPPED (git unavailable)")
    elif before != after:
        print("  ✗ selftest mutated the working tree")
        failures += 1
    else:
        print("  ✓ working tree unchanged (git status --porcelain identical)")

    if failures:
        print(f"\nselftest FAILED — {failures} case(s). The guard is not trustworthy.")
        return 1
    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Ban silent localhost gateway fallbacks in apps/web."
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant a fallback in a temp tree and prove the guard blocks it",
    )
    args = ap.parse_args()  # exits 2 on an unrecognised argument

    if args.selftest:
        return selftest()

    hits = scan(WEB, ROOT)
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

#!/usr/bin/env python3
"""check-client-bare-fetch — client code calls our own `/api/*` routes through `apiFetch` /
`apiFetchRaw`, never a bare `fetch`.

WHY (B-561, 2026-09-27). An expired session makes an API route redirect to `/sign-in`,
which redirects cross-origin to WorkOS. A bare `fetch` FOLLOWS that chain and dies on
CORS as a `TypeError` with nothing to read, so the island shows "failed to load" instead
of sending the person to sign in. `apiFetchRaw` (`apps/web/lib/api-fetch.ts`) does not
follow the redirect and navigates to `/sign-in?returnTo=…`. 64 call sites in 34 files
were migrated on 2026-09-27; this keeps the 65th from arriving.

Scope: `"use client"` files under apps/web/{app,components,lib}, tests excluded.
Server code (route handlers, server components) is not a browser and is out of scope.

Usage:  check-client-bare-fetch.py [--selftest]
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "apps" / "web"
DIRS = ("app", "components", "lib")
BARE = re.compile(r"""(?<![\w.])fetch\(\s*[`"']/api/""")
CLIENT = re.compile(r"""^\s*["']use client["']""", re.MULTILINE)


def scan(web: Path) -> list[str]:
    hits: list[str] = []
    for d in DIRS:
        base = web / d
        if not base.exists():
            continue
        for p in sorted(base.rglob("*.ts*")):
            if ".test." in p.name or p.name == "api-fetch.ts":
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            head = "\n".join(text.splitlines()[:3])
            if not CLIENT.search(head):
                continue
            lines = text.splitlines()
            for m in BARE.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                # Opt-out, one line, WITH a reason: `client-bare-fetch-ok: <why>` on the
                # same or the previous line (e.g. the error beacon, which must never
                # navigate away from the page it is reporting).
                near = " ".join(lines[max(0, line - 2) : line])
                if re.search(r"client-bare-fetch-ok:\s*\S", near):
                    continue
                hits.append(f"{p.relative_to(web.parent.parent)}:{line}")
    return hits


def selftest() -> int:
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        web = Path(td) / "apps" / "web"
        (web / "components").mkdir(parents=True)
        cases = {
            "bad-double.tsx": ('"use client";\nfetch("/api/x");\n', 1),
            "bad-template.tsx": (
                '"use client";\nconst r = await fetch(`/api/y/${id}`, {});\n',
                1,
            ),
            "bad-single.tsx": ("'use client';\nfetch('/api/z');\n", 1),
            "ok-helper.tsx": (
                '"use client";\nawait apiFetchRaw("/api/x");\napiFetch("/api/y");\n',
                0,
            ),
            "ok-server.tsx": ('import x from "y";\nfetch("/api/x");\n', 0),
            "ok-external.tsx": (
                '"use client";\nfetch("https://example.com/api/x");\n',
                0,
            ),
            "ok.test.tsx": ('"use client";\nfetch("/api/x");\n', 0),
            "ok-marked.tsx": (
                '"use client";\nfetch("/api/x"); // client-bare-fetch-ok: beacon never navigates\n',
                0,
            ),
            "bad-empty-marker.tsx": (
                '"use client";\nfetch("/api/x"); // client-bare-fetch-ok:\n',
                1,
            ),
        }
        for name, (body, _) in cases.items():
            (web / "components" / name).write_text(body)
        found = scan(web)
        for name, (_, want) in cases.items():
            got = sum(1 for h in found if h.endswith(f"{name}:2"))
            ok = got == want
            fails += 0 if ok else 1
            print(f"  {'✓' if ok else '✗'} {name}: {got} hit(s), want {want}")
    print(
        "client-bare-fetch selftest "
        + ("PASSED." if fails == 0 else f"FAILED ({fails}).")
    )
    return 0 if fails == 0 else 1


def main(argv: list[str]) -> int:
    if argv[1:] == ["--selftest"]:
        return selftest()
    if argv[1:]:
        print(f"usage: {Path(argv[0]).name} [--selftest]", file=sys.stderr)
        return 2
    hits = scan(WEB)
    if hits:
        print(
            "✗ client code calls /api/* with a bare fetch — use apiFetch / apiFetchRaw "
            "(apps/web/lib/api-fetch.ts), which sends an expired session to sign-in:"
        )
        for h in hits:
            print(f"    {h}")
        return 1
    print("OK — no bare fetch to /api/* in client code.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

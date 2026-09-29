#!/usr/bin/env python3
"""A Next.js route file exports ONLY what Next's contract allows.

WHY THIS EXISTS (2026-09-23). P0-4's `/settings/gateway` exported its view component
from `page.tsx` so the test could import it. Next 15 refuses any named value export
from a route file that is not one of its own contract fields, and the WEB DEPLOY DIED
on it:

    Type error: Page "app/settings/gateway/page.tsx" does not match the required
    types of a Next.js Page. "GatewaySettingsView" is not a valid Page export field.

THE POINT IS WHY NOTHING CAUGHT IT. `pnpm typecheck` runs `tsc`, which knows nothing
about Next's route contract. `next build` is the ONLY thing that enforces it, and the
full gate does not run `next build`. So 114 green checks, ~1,300 passing tests and a
clean typecheck all had nothing to say, and the class reached the deploy. This guard is
the cheap enforcement that belongs BEFORE the deploy rather than at it.

TYPE exports are fine and deliberately allowed — they are erased before Next sees them,
and the real build accepted `export type GatewaySettings` in the very file it rejected.
The fix for a hit is to move the value into a sibling module and import it, which is
what `DatasetAction.tsx` already does.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "apps" / "web" / "app"

ROUTE_FILES = {
    "page.tsx",
    "layout.tsx",
    "template.tsx",
    "error.tsx",
    "global-error.tsx",
    "loading.tsx",
    "not-found.tsx",
    "default.tsx",
}
ALLOWED = {
    "default",
    "metadata",
    "generateMetadata",
    "generateStaticParams",
    "dynamic",
    "dynamicParams",
    "revalidate",
    "fetchCache",
    "runtime",
    "preferredRegion",
    "maxDuration",
    "experimental_ppr",
    "viewport",
    "generateViewport",
    "config",
    "alt",
    "size",
    "contentType",
}
# `export type X` / `export interface X` are erased and never reach Next — excluded by
# requiring a value keyword here.
VALUE_EXPORT = re.compile(
    r"^export\s+(?:async\s+)?(?:function|const|let|var|class)\s+(\w+)", re.MULTILINE
)


def scan(app_dir: Path) -> list[str]:
    findings: list[str] = []
    for path in sorted(app_dir.rglob("*.tsx")):
        if path.name not in ROUTE_FILES or ".test." in path.name:
            continue
        src = path.read_text(encoding="utf-8", errors="replace")
        for m in VALUE_EXPORT.finditer(src):
            name = m.group(1)
            if name in ALLOWED:
                continue
            line = src.count("\n", 0, m.start()) + 1
            try:
                rel = path.relative_to(ROOT)
            except ValueError:
                rel = path  # selftest fixture lives outside the repo
            findings.append(
                f"{rel}:{line}: `export {name}` is not a Next route-contract field. "
                f"`next build` REFUSES this; tsc does not. Move it to a sibling module "
                f"and import it (see apps/web/app/datasets/DatasetAction.tsx)."
            )
    return findings


def selftest() -> int:
    ok = True
    with tempfile.TemporaryDirectory() as td:
        app = Path(td) / "app"
        (app / "good").mkdir(parents=True)
        (app / "bad").mkdir(parents=True)
        (app / "good" / "page.tsx").write_text(
            "export const metadata = {};\n"
            "export type Row = { a: string };\n"
            "export interface Props { b: number }\n"
            "export default function Page() { return null }\n"
        )
        (app / "bad" / "page.tsx").write_text(
            "export function SomeView() { return null }\n"
            "export default function Page() { return null }\n"
        )
        found = scan(app)
        bad = [f for f in found if "/bad/" in f]
        good = [f for f in found if "/good/" in f]
        if len(bad) == 1 and "SomeView" in bad[0]:
            print("  ✓ a non-contract value export BLOCKS")
        else:
            print(f"  ✗ expected 1 blocking finding for bad/page.tsx, got {bad}")
            ok = False
        if not good:
            print("  ✓ default + metadata + `export type` + `export interface` PASS")
        else:
            print(f"  ✗ good/page.tsx should be clean, got {good}")
            ok = False
        # A non-route file with the same export must be ignored entirely.
        (app / "good" / "Widget.tsx").write_text(
            "export function Widget() { return null }\n"
        )
        if not [f for f in scan(app) if "Widget" in f]:
            print("  ✓ a sibling component file is NOT a route file and is ignored")
        else:
            print("  ✗ a non-route .tsx was scanned")
            ok = False
    print("selftest PASSED." if ok else "selftest FAILED.")
    return 0 if ok else 1


def main() -> int:
    # REFUSE AN UNKNOWN FLAG. The meta-gate caught this guard exiting 0 for
    # `--tracelane-meta-gate-nonsense-flag`: a guard that ignores argv would run its
    # ordinary scan under ANY flag, so a green `--selftest` would prove nothing about
    # the selftest. That is the circular-selftest shape, and it was in the first draft
    # of this file.
    args = sys.argv[1:]
    unknown = [a for a in args if a != "--selftest"]
    if unknown:
        print(
            f"✗ unknown argument(s): {' '.join(unknown)} — this guard takes "
            "`--selftest` or nothing.",
            file=sys.stderr,
        )
        return 2
    if "--selftest" in args:
        return selftest()
    if not APP.is_dir():
        print(f"✗ CANNOT DETERMINE — {APP} is not a directory", file=sys.stderr)
        return 2
    findings = scan(APP)
    if findings:
        print("FAIL — Next route files export values Next's contract does not allow:")
        for f in findings:
            print(f"  {f}")
        return 1
    n = sum(
        1
        for p in APP.rglob("*.tsx")
        if p.name in ROUTE_FILES and ".test." not in p.name
    )
    print(f"next page exports: clean ({n} route file(s) checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

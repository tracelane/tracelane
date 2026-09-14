#!/usr/bin/env python3
"""apps/site declares its browser floor and its whitespace mode. Neither may be inherited.

WHY THIS EXISTS (B-373 / B-374, 2026-09-10). Bumping `astro` 6.4.8 -> 7.3.2 to close a
CRITICAL AVIF-decoder RCE changed the marketing site's rendered output twice, and BOTH
changes were invisible to every control this repo has — `astro check` reported 0 errors,
15 site tests passed, biome and the full gate were green:

  * `compressHTML` defaulted from `true` to `"jsx"`, which drops the whitespace BETWEEN
    INLINE ELEMENTS. Real copy came out as "licensed underApache 2.0", "The/spec
    directory", "5months", "14MB", "✓Apache 2.0", "provenPLT-23".
  * Vite's `baseline-widely-available` target is a MOVING one. Vite 7.3.6 resolves it to
    safari16; Vite 8.3.0 (which Astro 7 brings) resolves it to safari16.4 — the release
    that gained Media Queries Level 4 range syntax. Lightning CSS therefore stopped
    lowering it and ALL 22 `@media(min-width:…)` became `@media (width>=…)`. A browser
    under the floor does not degrade, it drops the whole query: every responsive rule on
    tracelane.dev would have stopped applying at once on iOS 16.0-16.3.

Both were found by diffing the built `dist/` against the previous build. Nothing else
could have found them, which is the point: **a framework bump can rewrite every rendered
byte of the public site while every gate stays green.**

So this makes the two decisions EXPLICIT and keeps them that way. An inherited default is
a decision nobody made, and the two above changed under us without a line of our code
moving.

  1. `build.cssTarget` is a literal list of browsers. Not absent (inherited), not
     `"baseline-widely-available"` (a moving alias whose meaning changes with Vite).
  2. `compressHTML` is set explicitly, to either value. The point is that a reader can
     see which whitespace semantics the site ships.

HONEST LIMIT, and it is the same shape as `check-spec-anchors.py`'s: this proves the
decision is WRITTEN DOWN, never that the rendered output is right. The output was
verified on 2026-09-10 by building both versions and comparing the extracted visible-text
stream of all seven pages — identical — plus element counts, ids and `src`s. Re-running
that comparison is what a reviewer owes the next framework bump; see B-374 for the
argument about turning it into a gate of its own.

USAGE
  check-site-browser-floor.py            # assert both decisions are declared
  check-site-browser-floor.py --selftest # prove each assertion BLOCKS
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "apps" / "site" / "astro.config.ts"

# A literal list: `cssTarget: ["chrome107", …]`. A bare string alias is REFUSED even
# when it names a real Vite target, because the alias is the moving part.
RE_CSS_TARGET_LIST = re.compile(r"cssTarget\s*:\s*\[([^\]]*)\]", re.DOTALL)
RE_CSS_TARGET_ANY = re.compile(r"cssTarget\s*:")
RE_COMPRESS_HTML = re.compile(r"compressHTML\s*:\s*(true|false|\"jsx\"|'jsx')")
RE_BROWSER = re.compile(r"^[a-z_]+\d+(\.\d+)?$")


def check(text: str) -> list[str]:
    failures: list[str] = []

    m = RE_CSS_TARGET_LIST.search(text)
    if not m:
        if RE_CSS_TARGET_ANY.search(text):
            failures.append(
                "`vite.build.cssTarget` is set to something other than a literal list of "
                'browsers. `"baseline-widely-available"` and friends are MOVING aliases — '
                "that is exactly how safari16 became safari16.4 and every media query on "
                "the site switched to range syntax (B-373). Name the browsers."
            )
        else:
            failures.append(
                "apps/site declares no `vite.build.cssTarget`, so its browser floor is "
                "whatever Vite's default happens to mean this release. That default moved "
                "under us once already and rewrote all 22 media queries into a syntax "
                "iOS 16.0-16.3 drops entirely (B-373). Declare the floor."
            )
    else:
        browsers = [b.strip().strip("\"'") for b in m.group(1).split(",") if b.strip()]
        if not browsers:
            failures.append("`cssTarget` is an EMPTY list — that is not a floor.")
        for b in browsers:
            if not RE_BROWSER.match(b):
                failures.append(
                    f"`cssTarget` entry {b!r} is not a `<browser><version>` literal "
                    f"(e.g. `safari16`, `chrome107`)."
                )

    if not RE_COMPRESS_HTML.search(text):
        failures.append(
            "apps/site does not set `compressHTML` explicitly. Astro 7 changed its "
            'default from `true` to `"jsx"`, which deletes the space between inline '
            'elements — the site rendered "licensed underApache 2.0" and "5months" '
            "before this was pinned (B-373). Whichever mode is wanted, say so."
        )

    return failures


def selftest() -> int:
    real = CONFIG.read_text(encoding="utf-8")
    cases: list[tuple[str, str, bool]] = [
        ("the real astro.config.ts passes", real, False),
        (
            "DELETING cssTarget blocks",
            re.sub(r"\n\s*cssTarget\s*:\s*\[[^\]]*\],", "", real),
            True,
        ),
        (
            "cssTarget as a MOVING alias blocks",
            re.sub(
                r"cssTarget\s*:\s*\[[^\]]*\]",
                'cssTarget: "baseline-widely-available"',
                real,
            ),
            True,
        ),
        (
            "an EMPTY cssTarget list blocks",
            re.sub(r"cssTarget\s*:\s*\[[^\]]*\]", "cssTarget: []", real),
            True,
        ),
        (
            "a non-literal browser entry blocks",
            re.sub(r"cssTarget\s*:\s*\[[^\]]*\]", 'cssTarget: ["modern"]', real),
            True,
        ),
        (
            "DELETING compressHTML blocks",
            real.replace("compressHTML: true,", ""),
            True,
        ),
        (
            "compressHTML set the OTHER way still passes — the point is that it is stated",
            real.replace("compressHTML: true,", 'compressHTML: "jsx",'),
            False,
        ),
    ]
    rc = 0
    for label, text, want_fail in cases:
        # A mutation that changed nothing would make its case vacuous — the anchor moved.
        if want_fail and text == real:
            print(f"  ✗ {label}: the mutation changed NOTHING — its anchor has moved")
            rc = 1
            continue
        failures = check(text)
        got_fail = bool(failures)
        ok = got_fail == want_fail
        print(f"  {'✔' if ok else '✗'} {label}: {'blocked' if got_fail else 'passed'}")
        if not ok:
            rc = 1
            for f in failures:
                print(f"      {f}")
    print("SELFTEST", "PASS" if rc == 0 else "FAIL")
    return rc


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--selftest":
        return selftest()
    if argv:
        print(f"unknown argument: {argv[0]}", file=sys.stderr)
        return 2
    failures = check(CONFIG.read_text(encoding="utf-8"))
    if failures:
        print("site browser floor: FAIL")
        for f in failures:
            print(f"  ✗ {f}")
        return 1
    print(
        "site browser floor: OK — apps/site declares an explicit cssTarget and an "
        "explicit compressHTML. Neither is inherited from a moving default."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

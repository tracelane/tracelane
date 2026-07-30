#!/usr/bin/env python3
"""Fail if the published docs site would 404 — nav, assets, links, MDX parse.

Why this exists (CLASS-1): `docs.tracelane.dev` shipped with `/architecture`,
`/pricing`, and `/changelog` in the left nav and 404 on the live site, plus a
navbar logo that rendered as the alt text "light logo". Nothing checked any of
it. The pages were fine as Markdown and broken as MDX; the logo paths in
`docs.json` pointed at files that existed nowhere in the repo.

Six checks, all of which were silently failing on 2026-07-29:

  1. NAV      — every page in `docs.json` navigation has a matching `.mdx`.
  2. EXPORT   — no nav page is dropped by `scripts/export/export-deny.txt`. Such
                a page exists locally and 404s only on the published site, so a
                private-tree check alone can never see it. This is exactly how
                `/changelog` shipped broken.
  3. ASSETS   — every asset `docs.json` references (logo light/dark, favicon)
                exists on disk. A missing logo renders as alt text.
  4. MDX      — no bare `<` outside code. MDX parses `<5ms` as a JSX tag open
                and refuses the whole page ("Unexpected character `5` before
                name"), so the page is dropped from the build and 404s while
                still sitting in the nav. Wrap comparisons in backticks.
  5. LINKS    — every internal body link `](/foo)` resolves to a real page.
  6. SOCIAL   — every social/identity link is an account we have CONFIRMED we
                own. A footer linked `x.com/tracelanedev`, an account that has
                never existed. Reachability cannot catch this class: a squatted
                handle returns 200, so the check is an allowlist, not a probe.

Mintlify's `{#custom-anchor}` heading syntax is stripped before the MDX scan —
it is valid there and verified rendering live.

Run `--selftest` to watch each check go red against a planted violation: a
guard that has never been observed blocking is not a guard.

Exit 1 on any hit, 0 when clean.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "apps" / "docs"

ANCHOR = re.compile(r"\{#[a-z0-9-]+\}")
# `<` that cannot open a JSX tag: not a letter, `/`, or `!` (comment) after it.
BARE_LT = re.compile(r"<(?![A-Za-z/!])")
BODY_LINK = re.compile(r"\]\((/[^)#\s]*)")


def nav_pages(cfg: dict) -> list[str]:
    out: list[str] = []
    for tab in cfg.get("navigation", {}).get("tabs", []):
        for group in tab.get("groups", []):
            out.extend(group.get("pages", []))
    return out


# Social/identity accounts we have CONFIRMED we control. Adding a row here is a
# claim of ownership — verify the account exists and is ours before you do.
# Confirmed 2026-07-29: x.com/xsanjeevlabs → 200; x.com/tracelanedev → 404 (never
# existed, shipped in the footer anyway). LinkedIn answers 999 to all automated
# requests, so /in/sanjeevlabs rests on the founder's confirmation, not a probe.
OWNED_ACCOUNTS = {
    "https://github.com/tracelane/tracelane",
    "https://github.com/tracelane",
    "https://x.com/xsanjeevlabs",
    "https://www.linkedin.com/in/sanjeevlabs",
}

SOCIAL_HOSTS = ("x.com", "twitter.com", "linkedin.com", "mastodon", "bsky.app")


def social_urls(cfg: dict) -> list[tuple[str, str]]:
    """(label, url) for every social/identity link in docs.json.

    Covers `footer.socials`, `navbar.links`, and `navbar.primary` — the footer is
    where the dead `x.com/tracelanedev` link lived, and the navbar is where the
    dead `status.tracelane.dev` button lived.
    """
    out: list[tuple[str, str]] = []
    for name, url in (cfg.get("footer", {}).get("socials") or {}).items():
        if isinstance(url, str):
            out.append((f"footer.socials.{name}", url))
    navbar = cfg.get("navbar") or {}
    for link in navbar.get("links") or []:
        href = link.get("href", "")
        if any(h in href for h in SOCIAL_HOSTS):
            out.append((f"navbar.links[{link.get('label', '?')}]", href))
    primary = navbar.get("primary") or {}
    if any(h in primary.get("href", "") for h in SOCIAL_HOSTS):
        out.append(("navbar.primary", primary["href"]))
    return out


def export_denied_pages() -> set[str] | None:
    """Doc slugs that `scripts/export/export-deny.txt` strips from the public repo.

    Resolved relative to this checkout, not to the docs dir under test — the
    selftest copies the docs tree to a tempdir but the deny-list lives with the
    repo.

    Returns ``None`` — not an empty set — when the deny-list is absent. That is
    the PUBLIC mirror: `scripts/export` is itself export-denied, so the file
    cannot be there and this check has no subject (the public repo IS the export;
    nothing downstream of it drops pages). Returning an empty set instead made the
    check silently no-op, which the selftest then correctly reported as decorative
    and failed the job — a control that is present, reported, and not load-bearing.
    ``None`` makes the distinction explicit so the selftest can SKIP it out loud
    rather than either lying green or failing red.
    """
    deny = ROOT / "scripts" / "export" / "export-deny.txt"
    if not deny.exists():
        return None
    out: set[str] = set()
    for raw in deny.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("apps/docs/") and line.endswith(".mdx"):
            out.add(line[len("apps/docs/") : -len(".mdx")])
    return out


def code_stripped(text: str) -> list[tuple[int, str]]:
    """Yield (lineno, line) with fenced blocks dropped and inline code blanked."""
    out: list[tuple[int, str]] = []
    fenced = False
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        out.append((i, re.sub(r"`[^`]*`", "", ANCHOR.sub("", line))))
    return out


def check(docs: Path) -> list[str]:
    hits: list[str] = []
    cfg_path = docs / "docs.json"
    if not cfg_path.exists():
        return [f"{cfg_path}: missing docs.json"]
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    pages = nav_pages(cfg)
    for page in pages:
        if not (docs / f"{page}.mdx").exists():
            hits.append(
                f"NAV     docs.json: '{page}' is in the navigation but {page}.mdx does not exist → 404"
            )

    # A nav page that EXISTS here but is denied from the public export is a
    # guaranteed 404 on the published site, and looks perfectly fine locally.
    # This is how /changelog shipped broken: export-deny.txt drops it, docs.json
    # kept listing it. Checking only the private tree would never catch that.
    for denied in export_denied_pages() or ():
        if denied in pages:
            hits.append(
                f"EXPORT  docs.json: '{denied}' is in the navigation but export-deny.txt "
                f"drops it from the public repo → 404 on the published site only"
            )

    # Social/identity links are IDENTITY CLAIMS — a link to an account we do not
    # own is a false claim, not a dead link, and no reachability check can tell
    # the difference (a squatted handle returns 200). So this is an allowlist of
    # accounts we have actually confirmed, checked offline and hard-failing.
    for label, url in social_urls(cfg):
        if url not in OWNED_ACCOUNTS:
            hits.append(
                f"SOCIAL  docs.json {label}: '{url}' is not in OWNED_ACCOUNTS → "
                f"unverified identity claim (x.com/tracelanedev shipped this way and 404'd)"
            )

    assets = [cfg.get("favicon")] + list((cfg.get("logo") or {}).values())
    for asset in [a for a in assets if isinstance(a, str)]:
        if not (docs / asset.lstrip("/")).exists():
            hits.append(
                f"ASSET   docs.json: references '{asset}' but no such file → renders as alt text"
            )

    known = {
        p.relative_to(docs).with_suffix("").as_posix() for p in docs.rglob("*.mdx")
    }
    for f in sorted(docs.rglob("*.mdx")):
        rel = f.relative_to(docs).as_posix()
        text = f.read_text(encoding="utf-8")
        for lineno, line in code_stripped(text):
            if BARE_LT.search(line):
                snippet = line.strip()[:70]
                hits.append(
                    f"MDX     {rel}:{lineno}: bare '<' breaks the MDX parse → page 404s: {snippet}"
                )
        for target in BODY_LINK.findall(text):
            slug = target.lstrip("/")
            if slug and slug not in known:
                hits.append(f"LINK    {rel}: links to '{target}' — no such page")
    return hits


SELFTEST_CASES = {
    "NAV": ("docs.json", lambda s: s.replace('"index"', '"index", "ghost-page"')),
    "ASSET": ("docs.json", lambda s: s.replace('"/favicon.svg"', '"/nope.svg"')),
    "MDX": ("index.mdx", lambda s: s + "\nGateway overhead is <5ms p99.\n"),
    "LINK": ("index.mdx", lambda s: s + "\nSee the [ghost](/nowhere-at-all).\n"),
    # Re-adds the exact nav entry that made /changelog 404 on the live site.
    "EXPORT": (
        "docs.json",
        lambda s: s.replace('"troubleshooting"', '"troubleshooting", "changelog"'),
    ),
    # Re-adds the exact dead handle that shipped in the footer.
    "SOCIAL": (
        "docs.json",
        lambda s: s.replace(
            '"x": "https://x.com/xsanjeevlabs"',
            '"x": "https://x.com/tracelanedev"',
        ),
    ),
}


def selftest() -> int:
    """Plant one violation per check and assert the guard goes red for each."""
    import shutil

    failures = 0
    # The EXPORT check has no subject in the public mirror: `scripts/export` is
    # export-denied, so export-deny.txt cannot be present there. Skip it ONLY on
    # that exact evidence — if the deny-list exists, the check must still be proven
    # discriminating, or a real regression could hide behind a "skip".
    inapplicable = {"EXPORT"} if export_denied_pages() is None else set()
    proven = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "docs"
        shutil.copytree(DOCS, base)
        if check(base):
            print("❌ selftest: baseline copy is already dirty — cannot falsify")
            return 1
        print("✓ selftest baseline clean")
        for label, (target, mutate) in SELFTEST_CASES.items():
            if label in inapplicable:
                print(
                    f"⊘ {label:7s} SKIPPED — no scripts/export/export-deny.txt in this "
                    f"checkout (public mirror: there is no export step to drop pages)"
                )
                continue
            path = base / target
            original = path.read_text(encoding="utf-8")
            path.write_text(mutate(original), encoding="utf-8")
            hits = [h for h in check(base) if h.startswith(label)]
            path.write_text(original, encoding="utf-8")
            if hits:
                print(f"✓ {label:7s} bites: {hits[0][:96]}")
                proven += 1
            else:
                print(f"❌ {label:7s} did NOT fire on a planted violation")
                failures += 1
    total = len(SELFTEST_CASES)
    if failures:
        print(f"\nselftest: {failures} check(s) decorative")
    elif inapplicable:
        print(
            f"\nselftest: {proven} of {total} checks proven discriminating; "
            f"{len(inapplicable)} not applicable here ({', '.join(sorted(inapplicable))})"
        )
    else:
        print(f"\nselftest: all {total} checks proven discriminating")
    return 1 if failures else 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    hits = check(DOCS)
    if hits:
        print("❌ docs site would 404 / render broken:")
        for h in hits:
            print(f"   {h}")
        print(
            "\n→ A page in the nav that fails to parse is dropped from the build and 404s "
            "while still showing in the sidebar. Wrap `<5ms`-style comparisons in backticks."
        )
        return 1
    print("✓ docs site: nav, assets, links, and MDX parse all clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())

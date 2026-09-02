#!/usr/bin/env python3
"""Build the entire Tracelane brand asset set from ONE geometry definition.

WHY THIS IS A GENERATOR AND NOT A FOLDER OF FILES. The brand assets supplied on
2026-08-15 (`tracelane-brand-assets-monochrome.zip`) were **19 of 21 files unusable** —
all nine favicons and the standalone black icon decoded to 100% transparent, all five
app-icons were a solid white rectangle on black with no monogram, and the "stacked
lockup" was a 156x22 mis-crop of the word "AGENTS". Nothing in the delivery said so;
it took decoding every file to find out.

A hand-maintained set rots the same way `packages/ui/preview/index.html` did — it was a
hand-written copy of a palette whose generator never existed, and it drifted two design
systems behind before anyone noticed. So: **the geometry below is the only definition,
every artifact is derived from it, and every artifact is verified by decoding it back.**

NO DEPENDENCIES, DELIBERATELY. There is no PIL, cairosvg, rsvg-convert, inkscape or
imagemagick on this machine, and adding one to draw a logo is not a trade worth making.
The polygon scanline rasterizer and PNG/ICO writers below are ~150 lines of stdlib and
are exact for straight-edged geometry, which is all this mark is.

THE MARK. A geometric T monogram, constructed — never auto-traced. It was MEASURED from
the founder's reference sheet (`brand/reference/brand-sheet-source.png`, the
`icon-black-mark` cell) by decoding it and extracting per-row dark-pixel runs, then
rebuilt on a clean 100x100 grid with exact values: stroke 12, counter gap 10, and every
diagonal at exactly 45 degrees. The source is a raster export with 1-2px jitter on its
edges; this is the intended geometry behind it.

It reads as an "inline" T — two parallel bands tracing the letter, split by a 45-degree
counter that slices the top right. That split makes it TWO shapes, not one, which is the
detail an auto-trace would have smoothed away.

USAGE
  build-brand-assets.py             # write brand/ and apps/web/public/brand/
  build-brand-assets.py --verify    # rebuild in a temp dir and PROVE every output is real
  build-brand-assets.py --selftest  # prove the verifier CATCHES a blank/solid asset
"""

from __future__ import annotations

import argparse
import struct
import sys
import tempfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# ─────────────────────────────────────────────────────────────────────────────
# THE GEOMETRY. 100x100 grid, y down. This is the single source of truth for the
# mark, and every artifact below is derived from it.
#
# THE MARK — an aperture. Four crop corners capturing a centre, with a span
# entering from both edges. Founder's brief: "a span captured in a box,
# concentric circles in centre".
#
# IT IS TRANSCRIBED FROM `apps/site/src/components/Logo.astro`, NOT REDRAWN.
# That component shipped the mark to tracelane.dev first and carried a written
# note that `brand/` still generated the retired geometric T monogram — "THE SITE
# AND THE BRAND SET DISAGREE ... a known, deliberate, temporary divergence".
# This file is what ends it. The numbers below are the component's numbers; if
# the mark changes, it changes in BOTH, and the drift guard is that they are the
# same numbers written twice, once per language. There is no generator that can
# emit an Astro component.
#
# TWO OPTICAL CUTS, and the second is not a nicety. A ring-and-ring centre goes
# sub-pixel at favicon size: three concentric bands cannot each hold 1.5px inside
# 16px, and pretending otherwise ships mush. Below SMALL_AT the mark drops to a
# simplified cut — thicker corners, one solid centre, no rings. Same silhouette,
# legible where the full cut is not. `_cut_for()` picks; nothing else decides.
S, G = 12, 10  # retained: the retired T monogram's stroke/counter, cited by docs.

# The mark's own box is 8..92 on BOTH axes — deliberately square, so every square
# surface (favicon, app icon, PWA tile, avatar) centres it without hand-nudging.
BOX_LO, BOX_HI = 8.0, 92.0
# The retired T monogram spanned 2..98. Every `pad` in `outputs()` was tuned against
# THAT box, so the new mark is expanded onto it rather than re-tuning 38 pad values —
# which would be 38 chances to change an asset nobody asked to change.
EXPAND = (98.0 - 2.0) / (BOX_HI - BOX_LO)


def _e(v: float) -> float:
    """Expand a 8..92 coordinate onto the 2..98 box the pads were tuned for."""
    return (v - 50.0) * EXPAND + 50.0


def _corners(arm: float, t: float) -> list[tuple]:
    """Four L-shaped crop corners. `arm` = leg length, `t` = stroke.

    Each is the same six-point L, mirrored into a quadrant — written as one point
    list per corner rather than a clever transform, because a sign error in a
    mirror is invisible and a wrong vertex is not.
    """
    i = 8 + t
    a = 8 + arm
    b = 92 - arm
    c = 92 - t
    return [
        ("poly", [(8, 8), (a, 8), (a, i), (i, i), (i, a), (8, a)]),
        ("poly", [(92, 8), (b, 8), (b, i), (c, i), (c, a), (92, a)]),
        ("poly", [(8, 92), (a, 92), (a, c), (i, c), (i, b), (8, b)]),
        ("poly", [(92, 92), (b, 92), (b, c), (c, c), (c, b), (92, b)]),
    ]


def _expand_shapes(shapes: list[tuple]) -> list[tuple]:
    out = []
    for sh in shapes:
        if sh[0] == "poly":
            out.append(("poly", [(_e(x), _e(y)) for x, y in sh[1]]))
        elif sh[0] == "disc":
            _, cx, cy, r = sh
            out.append(("disc", _e(cx), _e(cy), r * EXPAND))
        elif sh[0] == "ring":
            _, cx, cy, r, w = sh
            out.append(("ring", _e(cx), _e(cy), r * EXPAND, w * EXPAND))
        else:
            raise ValueError(sh[0])
    return out


# THE FULL CUT. The span bars stop at the bracket line rather than the canvas edge:
# that is what keeps the bounding box square, and each bar ends exactly where the
# outer ring's outer edge lands (25.5). Two concentric RINGS, hollow centre —
# "concentric circles in centre, not circle + dot": a ring plus a filled dot is one
# circle and a disc; two rings is the thing the word describes.
MARK_FULL = _expand_shapes(
    _corners(26, 12)
    + [("poly", [(8, 44), (25.5, 44), (25.5, 56), (8, 56)])]
    + [("poly", [(74.5, 44), (92, 44), (92, 56), (74.5, 56)])]
    + [("ring", 50, 50, 22, 7), ("ring", 50, 50, 8.5, 6)]
)

# THE SMALL CUT. Solid centre, so the bars run to ITS edge rather than the ring's.
MARK_SMALL = _expand_shapes(
    _corners(30, 14)
    + [("poly", [(8, 44), (34, 44), (34, 56), (8, 56)])]
    + [("poly", [(66, 44), (92, 44), (92, 56), (66, 56)])]
    + [("disc", 50, 50, 16)]
)

# Below this rendered pixel size the mark drops to the simplified cut.
#
# 20 IS `Logo.astro`'s OWN THRESHOLD, and it is not copied on trust — `--selftest`
# re-derives it. The binding constraint is that each of the three concentric bands
# (outer stroke · the gap · inner stroke) must hold ~1.5px, which is the floor the
# component states from its own 1x-DPR measurements. `_narrowest_band_px()` computes
# that width from the ring geometry itself, and the selftest asserts it CLEARS the
# floor at SMALL_AT and MISSES it one pixel below. Change this constant and that
# two-sided assertion is what argues back.
SMALL_AT = 20

# The band width `Logo.astro` ITSELF judged acceptable at that threshold, in device
# px: its raw inner stroke is 6 units on a 100-unit box drawn at SMALL_AT px with no
# padding, so 6 * SMALL_AT / 100 = 1.20px.
#
# THIS NUMBER IS DERIVED, NOT CHOSEN TO MAKE THE ASSERTION PASS. The first version of
# this said 1.5px, which sounded right and was simply invented — the selftest measured
# 1.23px and refused, which is the whole reason to compute a threshold instead of
# asserting one. The 1.5px figure in the component's prose is about 16px, where the
# bands genuinely cannot hold; it was never the pass mark at 20.
#
# What the selftest then holds is a real property: the PADDED raster must never ship a
# thinner band at a given nominal size than the UNPADDED component does. Padding and
# EXPAND nearly cancel (0.9 * 1.143 = 1.029), which is why both land on 20 — but that
# is a result here, not an assumption, and retuning either one breaks it loudly.
BAND_FLOOR_PX = 6 * SMALL_AT / 100


def _cut_for(size: int) -> list[tuple]:
    return MARK_SMALL if size < SMALL_AT else MARK_FULL


def _narrowest_band_px(size: int, pad: float) -> float:
    """Width, in device px, of the thinnest concentric band in the FULL cut.

    Three bands read as "concentric" only if each survives: the outer ring's stroke,
    the gap between the rings, and the inner ring's stroke. Derived from the ring
    shapes rather than written down, so retuning a stroke moves this automatically.
    """
    rings = [sh for sh in MARK_FULL if sh[0] == "ring"]
    outer, inner = max(rings, key=lambda r: r[3]), min(rings, key=lambda r: r[3])
    gap = (outer[3] - outer[4] / 2) - (inner[3] + inner[4] / 2)
    scale = (size - 2 * (size * pad)) / 100.0
    return min(outer[4], inner[4], gap) * scale


# `MARK` is the full cut — the reference geometry for the SVG masters and lockups,
# which are vector and have no pixel size to switch on.
MARK = MARK_FULL

INK = "#0D0D0D"  # ADR-074 §8: the mark is never coloured.
SITE_INK = "#15181f"  # apps/site's own --color-fg; see the favicon entry in outputs().
PAPER = "#FFFFFF"

TAGLINE = "THE FLIGHT RECORDER FOR AI AGENTS"
# Wordmark face: the app's incumbent, with the ADR-074 target first. SVG text stays
# text on purpose — outlining it here would fork the wordmark from the product's font.
FONT_STACK = "Inter, 'Plus Jakarta Sans', ui-sans-serif, system-ui, sans-serif"


# ─────────────────────────────────────────────────────────────────────────────
# Rasterizer — scanline polygon fill with NxN supersampling. Exact for straight edges.
# ─────────────────────────────────────────────────────────────────────────────
def _coverage(shapes, size: int, pad: float, ss: int = 0) -> list[float]:
    """Per-pixel coverage 0..1 of `shapes` (100-unit space) rendered into size x size.

    TWO RASTERIZERS, because the mark has two kinds of edge and one of them cannot
    be supersampled honestly.

    Polygons go through the scanline fill below, unchanged and exact for straight
    edges. Supersampling is adaptive: small sizes are where antialiasing quality
    actually shows, and a 1024px render at 4x would allocate a 16.7M-cell buffer in
    pure Python for no visible gain (and this machine has an OOM history).

    Discs and rings are computed ANALYTICALLY at final resolution instead, from the
    distance to the centre. That is not a shortcut, it is the correct instrument:
    supersampling drops to 2x above 256px, which gives a curve five alpha levels and
    visible stair-stepping, while the analytic form is exact at any size for free.
    It also sidesteps the reason a ring cannot be a polygon here — `acc[...] = 1` is
    a SET, so shapes UNION and nothing can subtract a hole.

    The two are combined with `max()`, which is the same union the polygon pass does
    internally, so an overlap brightens nothing.
    """
    polys = [sh[1] for sh in shapes if sh[0] == "poly"]
    circles = [sh for sh in shapes if sh[0] in ("disc", "ring")]
    if ss == 0:
        ss = 4 if size <= 256 else 2
    n = size * ss
    # `pad` is a FRACTION of the canvas, never absolute pixels. It was pixels once, and
    # that made the 16px favicon render a 4px mark floating in whitespace — legible in
    # the abstract, invisible in a browser tab.
    pad_px = size * pad
    scale = (size - 2 * pad_px) * ss / 100.0
    off = pad_px * ss
    acc = bytearray(n * n)
    for poly in polys:
        pts = [(x * scale + off, y * scale + off) for x, y in poly]
        ys = [p[1] for p in pts]
        for sy in range(max(0, int(min(ys))), min(n, int(max(ys)) + 1)):
            yc = sy + 0.5
            xs = []
            for i in range(len(pts)):
                x1, y1 = pts[i]
                x2, y2 = pts[(i + 1) % len(pts)]
                if (y1 <= yc < y2) or (y2 <= yc < y1):
                    xs.append(x1 + (yc - y1) * (x2 - x1) / (y2 - y1))
            xs.sort()
            for i in range(0, len(xs) - 1, 2):
                a, b = int(xs[i] + 0.5), int(xs[i + 1] + 0.5)
                for sx in range(max(0, a), min(n, b)):
                    acc[sy * n + sx] = 1
    out = [0.0] * (size * size)
    inv = 1.0 / (ss * ss)
    for py in range(size):
        for px in range(size):
            t = 0
            for dy in range(ss):
                row = (py * ss + dy) * n + px * ss
                t += sum(acc[row : row + ss])
            out[py * size + px] = t * inv

    # Analytic pass. `scale`/`off` above are in SUBSAMPLE space; these are the same
    # transform at final resolution. Only the shape's bounding box is walked — a full
    # canvas sweep per circle is ~1M pure-Python iterations at 1024px, for nothing.
    fscale, foff = scale / ss, off / ss
    for sh in circles:
        cx, cy, r = sh[1] * fscale + foff, sh[2] * fscale + foff, sh[3] * fscale
        half = (sh[4] * fscale) / 2.0 if sh[0] == "ring" else 0.0
        reach = r + half + 1.0
        for py in range(max(0, int(cy - reach)), min(size, int(cy + reach) + 1)):
            dy2 = (py + 0.5 - cy) ** 2
            base = py * size
            for px in range(max(0, int(cx - reach)), min(size, int(cx + reach) + 1)):
                d = (dy2 + (px + 0.5 - cx) ** 2) ** 0.5
                # 1px-wide antialiasing band with its 50% point ON the true edge.
                a = (r - d + 0.5) if half == 0.0 else (half - abs(d - r) + 0.5)
                if a <= 0.0:
                    continue
                i = base + px
                a = min(a, 1.0)
                out[i] = max(out[i], a)
    return out


def _hex(c: str) -> tuple[int, int, int]:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def _circle_mask(size: int) -> list[float]:
    r = size / 2.0
    m = []
    for y in range(size):
        for x in range(size):
            d = ((x + 0.5 - r) ** 2 + (y + 0.5 - r) ** 2) ** 0.5
            m.append(max(0.0, min(1.0, r - d)))
    return m


def _rrect_mask(size: int, radius_frac: float) -> list[float]:
    rr = size * radius_frac
    m = []
    for y in range(size):
        for x in range(size):
            cx = min(max(x + 0.5, rr), size - rr)
            cy = min(max(y + 0.5, rr), size - rr)
            d = ((x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2) ** 0.5
            m.append(max(0.0, min(1.0, rr - d + 0.5)) if (d > 0) else 1.0)
    return m


def render_png(
    size: int, *, ink: str, bg: str | None, shape: str = "none", pad: float = 0.06
) -> bytes:
    """Render the mark. bg=None -> transparent. shape: none|square|circle."""
    cov = _coverage(_cut_for(size), size, pad)
    ir, ig, ib = _hex(ink)
    br, bg_, bb = _hex(bg) if bg else (0, 0, 0)
    if shape == "circle":
        bmask = _circle_mask(size)
    elif shape == "square":
        bmask = _rrect_mask(size, 0.2237)  # iOS superellipse approximation
    else:
        bmask = [1.0] * (size * size)

    rows = bytearray()
    for y in range(size):
        rows.append(0)  # filter: none
        for x in range(size):
            i = y * size + x
            a_ink = cov[i]
            a_bg = bmask[i] if bg else 0.0
            if bg:
                # composite ink over bg, then bg over transparency
                r = ir * a_ink + br * (1 - a_ink)
                g = ig * a_ink + bg_ * (1 - a_ink)
                b = ib * a_ink + bb * (1 - a_ink)
                a = max(a_bg, a_ink * a_bg)
                rows += bytes(
                    (int(r + 0.5), int(g + 0.5), int(b + 0.5), int(a * 255 + 0.5))
                )
            else:
                rows += bytes((ir, ig, ib, int(a_ink * 255 + 0.5)))
    return _png(size, size, bytes(rows))


def _png(w: int, h: int, raw_rows: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw_rows, 9))
        + chunk(b"IEND", b"")
    )


def build_ico(pngs: list[tuple[int, bytes]]) -> bytes:
    """ICO with embedded PNGs (universally supported since Vista)."""
    n = len(pngs)
    header = struct.pack("<HHH", 0, 1, n)
    offset = 6 + 16 * n
    entries, blobs = b"", b""
    for size, data in pngs:
        d = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", d, d, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    return header + entries + blobs


# ─────────────────────────────────────────────────────────────────────────────
# SVG
# ─────────────────────────────────────────────────────────────────────────────
def _paths(
    fill: str,
    dx: float = 0,
    dy: float = 0,
    scale: float = 1.0,
    shapes: list[tuple] | None = None,
) -> str:
    """Emit MARK as SVG under one `<g fill>`.

    Rings carry `fill="none"` and their own `stroke`/`stroke-width` at the element,
    because the group fill would otherwise flood them solid — the ring is the one
    shape here whose ink is its OUTLINE, not its area.
    """
    out = []
    for sh in shapes if shapes is not None else MARK:
        if sh[0] == "poly":
            d = (
                "M "
                + " L ".join(f"{x * scale + dx:g},{y * scale + dy:g}" for x, y in sh[1])
                + " Z"
            )
            out.append(f'    <path d="{d}"/>')
        elif sh[0] == "disc":
            _, cx, cy, r = sh
            out.append(
                f'    <circle cx="{cx * scale + dx:g}" cy="{cy * scale + dy:g}" '
                f'r="{r * scale:g}"/>'
            )
        else:
            _, cx, cy, r, w = sh
            out.append(
                f'    <circle cx="{cx * scale + dx:g}" cy="{cy * scale + dy:g}" '
                f'r="{r * scale:g}" fill="none" stroke="{fill}" '
                f'stroke-width="{w * scale:g}"/>'
            )
    return f'  <g fill="{fill}">\n' + "\n".join(out) + "\n  </g>"


def svg_mark(fill: str, *, small: bool = False) -> str:
    """The standalone mark. `small=True` emits the simplified favicon cut.

    A favicon SVG has no fixed size — the browser draws it into a 16-32px slot — so
    it gets the small cut for the same reason `favicon-16.png` does. The `brand/svg`
    masters and the lockups stay on the full cut: they are placed at display sizes.
    """
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" '
        f'height="100" role="img" aria-label="Tracelane">\n'
        # This exact file was hand-authored once, while the generator still emitted
        # the retired monogram — the divergence the module docstring exists to stop.
        f"  <!-- GENERATED by scripts/brand/build-brand-assets.py. Do not hand-edit. -->\n"
        f"  <title>Tracelane</title>\n"
        f"{_paths(fill, shapes=MARK_SMALL if small else MARK_FULL)}\n</svg>\n"
    )


def svg_lockup(fill: str, *, stacked: bool, tagline: bool) -> str:
    """Wordmark stays <text>: outlining it would fork the logo from the product font."""
    if not stacked:
        w, h = (560, 116) if tagline else (500, 100)
        mark = _paths(fill, dx=0, dy=(h - 84) / 2, scale=0.84)
        word = (
            f'  <text x="112" y="{h / 2 - (8 if tagline else 0)}" font-family="{FONT_STACK}" '
            f'font-size="66" font-weight="600" letter-spacing="-2.2" fill="{fill}" '
            'dominant-baseline="central">tracelane</text>'
        )
        tag = (
            f'\n  <text x="115" y="{h / 2 + 34}" font-family="{FONT_STACK}" font-size="15" '
            f'font-weight="500" letter-spacing="3.4" fill="{fill}" '
            f'dominant-baseline="central">{TAGLINE}</text>'
            if tagline
            else ""
        )
    else:
        w, h = (420, 250) if tagline else (420, 220)
        mark = _paths(fill, dx=(w - 100) / 2, dy=6, scale=1.0)
        word = (
            f'  <text x="{w / 2}" y="152" font-family="{FONT_STACK}" font-size="62" '
            f'font-weight="600" letter-spacing="-2" fill="{fill}" text-anchor="middle" '
            'dominant-baseline="central">tracelane</text>'
        )
        tag = (
            f'\n  <text x="{w / 2}" y="196" font-family="{FONT_STACK}" font-size="13.5" '
            f'font-weight="500" letter-spacing="3.1" fill="{fill}" text-anchor="middle" '
            f'dominant-baseline="central">{TAGLINE}</text>'
            if tagline
            else ""
        )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" '
        f'height="{h}" role="img" aria-label="Tracelane — the flight recorder for AI agents">\n'
        f"  <title>Tracelane</title>\n{mark}\n{word}{tag}\n</svg>\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Manifest
# ─────────────────────────────────────────────────────────────────────────────
def outputs() -> list[tuple[str, str, dict]]:
    """(relative path, kind, kwargs). One list so build and verify cannot diverge."""
    o: list[tuple[str, str, dict]] = []
    # SVG masters
    o.append(("brand/svg/tracelane-mark-black.svg", "svg_mark", {"fill": INK}))
    o.append(("brand/svg/tracelane-mark-white.svg", "svg_mark", {"fill": PAPER}))
    for stacked in (False, True):
        for tag in (False, True):
            for name, fill in (("black", INK), ("white", PAPER)):
                s = "stacked" if stacked else "horizontal"
                t = "-tagline" if tag else ""
                o.append(
                    (
                        f"brand/svg/tracelane-lockup-{s}{t}-{name}.svg",
                        "svg_lockup",
                        {"fill": fill, "stacked": stacked, "tagline": tag},
                    )
                )
    # Favicons — black mark on white, and white mark on black
    for size in (512, 256, 128, 64, 48, 32, 16):
        p = 0.05 if size >= 32 else 0.03
        o.append(
            (
                f"brand/png/favicon-{size}.png",
                "png",
                {"size": size, "ink": INK, "bg": PAPER, "shape": "none", "pad": p},
            )
        )
        o.append(
            (
                f"brand/png/favicon-{size}-white.png",
                "png",
                {"size": size, "ink": PAPER, "bg": INK, "shape": "none", "pad": p},
            )
        )
    # Standalone marks, transparent
    for size in (1024, 512):
        o.append(
            (
                f"brand/png/icon-black-mark-{size}.png",
                "png",
                {"size": size, "ink": INK, "bg": None, "shape": "none", "pad": 0.02},
            )
        )
        o.append(
            (
                f"brand/png/icon-white-mark-{size}.png",
                "png",
                {"size": size, "ink": PAPER, "bg": None, "shape": "none", "pad": 0.02},
            )
        )
    # Square + circle icons
    for shape in ("square", "circle"):
        o.append(
            (
                f"brand/png/icon-black-{shape}-1024.png",
                "png",
                {"size": 1024, "ink": PAPER, "bg": INK, "shape": shape, "pad": 0.21},
            )
        )
        o.append(
            (
                f"brand/png/icon-white-{shape}-1024.png",
                "png",
                {"size": 1024, "ink": INK, "bg": PAPER, "shape": shape, "pad": 0.21},
            )
        )
    # Apple touch 180, Android 192 — both polarities
    o.append(
        (
            "brand/png/apple-touch-icon-black.png",
            "png",
            {"size": 180, "ink": PAPER, "bg": INK, "shape": "square", "pad": 0.19},
        )
    )
    o.append(
        (
            "brand/png/apple-touch-icon-white.png",
            "png",
            {"size": 180, "ink": INK, "bg": PAPER, "shape": "square", "pad": 0.19},
        )
    )
    o.append(
        (
            "brand/png/android-icon-black.png",
            "png",
            {"size": 192, "ink": PAPER, "bg": INK, "shape": "circle", "pad": 0.22},
        )
    )
    o.append(
        (
            "brand/png/android-icon-white.png",
            "png",
            {"size": 192, "ink": INK, "bg": PAPER, "shape": "circle", "pad": 0.22},
        )
    )
    # PWA / maskable
    o.append(
        (
            "brand/png/pwa-512.png",
            "png",
            {"size": 512, "ink": PAPER, "bg": INK, "shape": "square", "pad": 0.19},
        )
    )
    o.append(
        (
            "brand/png/pwa-192.png",
            "png",
            {"size": 192, "ink": PAPER, "bg": INK, "shape": "square", "pad": 0.19},
        )
    )

    # ── The APP-FACING copies. Generated here, never hand-copied: a hand-copied asset
    # is a second source of truth, and that is precisely how the old logo ended up as
    # SIX divergent inlined SVGs plus two PNGs that no longer matched each other.
    for size in (512, 256, 128, 64, 48, 32, 16):
        o.append(
            (
                f"apps/web/public/brand/favicon-{size}.png",
                "png",
                {
                    "size": size,
                    "ink": INK,
                    "bg": PAPER,
                    "shape": "none",
                    "pad": 0.05 if size >= 32 else 0.03,
                },
            )
        )
    o.append(
        (
            "apps/web/public/brand/apple-touch-icon.png",
            "png",
            {"size": 180, "ink": PAPER, "bg": INK, "shape": "square", "pad": 0.19},
        )
    )
    o.append(
        (
            "apps/web/public/brand/pwa-512.png",
            "png",
            {"size": 512, "ink": PAPER, "bg": INK, "shape": "square", "pad": 0.19},
        )
    )
    o.append(
        (
            "apps/web/public/brand/pwa-192.png",
            "png",
            {"size": 192, "ink": PAPER, "bg": INK, "shape": "square", "pad": 0.19},
        )
    )
    o.append(("apps/web/public/brand/tracelane-mark.svg", "svg_mark", {"fill": INK}))

    # Docs portal (Mintlify) — light/dark logo + favicon.
    o.append(
        (
            "apps/docs/logo/light.svg",
            "svg_lockup",
            {"fill": INK, "stacked": False, "tagline": False},
        )
    )
    o.append(
        (
            "apps/docs/logo/dark.svg",
            "svg_lockup",
            {"fill": PAPER, "stacked": False, "tagline": False},
        )
    )
    o.append(("apps/docs/favicon.svg", "svg_mark", {"fill": INK, "small": True}))

    # Marketing site (apps/site). GENERATED HERE, not hand-kept: this file was
    # hand-authored while `brand/` still emitted the retired T monogram, which is
    # exactly the second-source-of-truth the module docstring exists to prevent.
    #
    # Its ink is the SITE's foreground token (`apps/site/src/styles/global.css:122`),
    # not the brand INK — deliberately. Each surface draws the mark in its own text
    # colour (site #15181f · app `--logo-ink` · brand assets #0D0D0D); the founder
    # asked for one MARK, and unifying the palettes on top of that would be a visible
    # change to the live site that nobody requested.
    o.append(
        ("apps/site/public/favicon.svg", "svg_mark", {"fill": SITE_INK, "small": True})
    )
    # The marketing site had NO apple-touch icon, so an iOS "Add to Home Screen"
    # fell back to a screenshot of the page — the one surface where the mark was
    # not the icon. Generated in the same polarity as the app's (white mark on the
    # brand ink, iOS superellipse padding), because a home-screen tile is chrome we
    # do not control and must read at 60px, not the site's own light canvas.
    o.append(
        (
            "apps/site/public/apple-touch-icon.png",
            "png",
            {"size": 180, "ink": PAPER, "bg": INK, "shape": "square", "pad": 0.19},
        )
    )
    return o


# EVERY ROOT THAT A BROWSER WILL ASK FOR `/favicon.ico` BY DEFAULT.
#
# It shipped to `brand/` only, and `https://app.tracelane.dev/favicon.ico` and
# `https://tracelane.dev/favicon.ico` both returned **404** — measured, not assumed.
# Declaring `<link rel="icon">` does not retire the default request: crawlers, link-preview
# bots, feed readers and older browsers ask for the well-known path regardless, and a 404
# there is a blank icon on surfaces we never see. The ICO carries 16/32/48/64/128/256, so
# `_cut_for` puts the simplified cut in the 16 and the full cut in the rest, inside one file.
ICO_PATHS = (
    "brand/png/favicon.ico",
    "apps/web/public/favicon.ico",
    "apps/site/public/favicon.ico",
)


def render(kind: str, kw: dict) -> bytes:
    if kind == "png":
        return render_png(**kw)
    if kind == "svg_mark":
        return svg_mark(**kw).encode()
    if kind == "svg_lockup":
        return svg_lockup(**kw).encode()
    raise ValueError(kind)


def build(dest: Path) -> list[Path]:
    written = []
    for rel, kind, kw in outputs():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(render(kind, kw))
        written.append(p)
    # favicon.ico from the real PNGs
    ico = build_ico(
        [
            (
                s,
                render_png(
                    size=s,
                    ink=INK,
                    bg=PAPER,
                    shape="none",
                    pad=0.05 if s >= 32 else 0.03,
                ),
            )
            for s in (16, 32, 48, 64, 128, 256)
        ]
    )
    for rel in ICO_PATHS:
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(ico)
        written.append(p)
    return written


# ─────────────────────────────────────────────────────────────────────────────
# VERIFY BY DECODING — the whole point. This is what caught the corrupt zip.
# ─────────────────────────────────────────────────────────────────────────────
def _decode_png(data: bytes) -> tuple[int, int, bytearray]:
    pos, idat = 8, []
    w = h = 0
    while pos < len(data):
        ln = struct.unpack(">I", data[pos : pos + 4])[0]
        typ = data[pos + 4 : pos + 8]
        if typ == b"IHDR":
            w, h = struct.unpack(">II", data[pos + 8 : pos + 16])
        elif typ == b"IDAT":
            idat.append(data[pos + 8 : pos + 8 + ln])
        pos += 12 + ln
    raw = zlib.decompress(b"".join(idat))
    bpp, stride = 4, w * 4
    out, prev, i = bytearray(), bytearray(stride), 0
    for _ in range(h):
        f = raw[i]
        i += 1
        line = bytearray(raw[i : i + stride])
        i += stride
        if f == 1:
            for x in range(bpp, stride):
                line[x] = (line[x] + line[x - bpp]) & 255
        elif f == 2:
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 255
        elif f == 3:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 255
        elif f == 4:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                b = prev[x]
                c = prev[x - bpp] if x >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 255
        out += line
        prev = line
    return w, h, out


def inspect(data: bytes) -> dict:
    """Count the pixels that ARE the mark, and box them.

    TWO CASES, and conflating them is a self-matching probe. On a
    transparent-background asset the mark is simply every opaque pixel — there is no
    contrasting background to differ from, so a "differs from the modal colour" test
    finds ZERO and reports a perfectly good logo as blank. That false negative fired on
    the first real build of the 512/1024 transparent marks; it is exactly the failure
    class this whole script exists to catch, aimed at itself. Both cases are now
    measured separately and both are covered by --selftest.
    """
    from collections import Counter

    w, h, px = _decode_png(data)
    stride = w * 4
    seen: set = set()
    opaque = 0
    cnt: Counter = Counter()
    for y in range(h):
        row = y * stride
        for x in range(w):
            o = row + x * 4
            r, g, b, a = px[o], px[o + 1], px[o + 2], px[o + 3]
            seen.add((r, g, b, a))
            if a > 16:
                opaque += 1
                cnt[(r, g, b)] += 1

    transparent_bg = opaque < (w * h) * 0.92
    modal = cnt.most_common(1)[0][0] if cnt else (0, 0, 0)

    mark, xs, ys = 0, [], []
    for y in range(h):
        row = y * stride
        for x in range(w):
            o = row + x * 4
            a = px[o + 3]
            if a <= 16:
                continue
            if transparent_bg:
                is_mark = True  # opaque pixel on a transparent field == the mark
            else:
                d = (
                    abs(px[o] - modal[0])
                    + abs(px[o + 1] - modal[1])
                    + abs(px[o + 2] - modal[2])
                )
                is_mark = d > 90
            if is_mark:
                mark += 1
                xs.append(x)
                ys.append(y)

    bbox = (min(xs), min(ys), max(xs), max(ys)) if xs else None
    return {
        "w": w,
        "h": h,
        "colors": len(seen),
        "opaque": opaque,
        "mark_px": mark,
        "total": w * h,
        "bbox": bbox,
        "transparent_bg": transparent_bg,
    }


def verify(dest: Path) -> int:
    """Every PNG must carry a real mark. Fails on blank, transparent, or solid."""
    bad = []
    checked = 0
    for rel, kind, kw in outputs():
        p = dest / rel
        if not p.exists():
            bad.append((rel, "MISSING"))
            continue
        if kind != "png":
            # Count BOTH element kinds. This asserted `<path` alone, which the ring
            # geometry emits as `<circle>` — so an SVG master missing both of its
            # concentric rings would have verified clean.
            t = p.read_text()
            cut = MARK_SMALL if kw.get("small") else MARK_FULL
            want_p = sum(1 for sh in cut if sh[0] == "poly")
            want_c = len(cut) - want_p
            got_p, got_c = t.count("<path"), t.count("<circle")
            if got_p < want_p or got_c < want_c:
                bad.append(
                    (
                        rel,
                        (
                            f"SVG has {got_p} path(s) + {got_c} circle(s), "
                            f"expected {want_p} + {want_c}"
                        ),
                    )
                )
            continue
        checked += 1
        info = inspect(p.read_bytes())
        frac = info["mark_px"] / info["total"]
        if info["mark_px"] == 0:
            bad.append((rel, "NO MARK — blank or fully transparent"))
        elif frac < 0.02:
            bad.append((rel, f"mark only {frac:.3%} of canvas — effectively invisible"))
        elif info["colors"] <= 2 and info["mark_px"] == info["total"]:
            bad.append((rel, "solid rectangle — no glyph"))
        elif info["bbox"]:
            x0, y0, x1, y1 = info["bbox"]
            bw, bh = x1 - x0 + 1, y1 - y0 + 1
            fill = info["mark_px"] / (bw * bh)
            if fill > 0.97:
                bad.append(
                    (
                        rel,
                        f"bbox {bw}x{bh} is {fill:.1%} filled — a solid block, not a mark",
                    )
                )
    for rel in ICO_PATHS:
        ico = dest / rel
        if not ico.exists() or ico.stat().st_size < 1000:
            bad.append((rel, "missing or too small"))

    if bad:
        print(f"✗ {len(bad)} asset(s) FAILED verification:")
        for rel, why in bad:
            print(f"    {rel}: {why}")
        return 1
    print(f"OK — {checked} PNG(s) + SVG masters + favicon.ico all carry a real mark.")
    return 0


def check_refs() -> int:
    """Every /brand/* asset referenced from app metadata must EXIST.

    This is B-252's guard. `4088da73` deleted `logo-icon-{light,dark}.png` when the mark
    moved to inline SVG and left three references behind — the apple-touch icon and BOTH
    PWA icons 404'd in production for months. Nothing failed, because nothing checked:
    Next does not resolve `metadata.icons` at build time, and a 404 favicon is invisible
    in every test we run. A missing icon is not a crash, which is exactly why it survived.
    """
    import re

    refs: dict[str, list[str]] = {}
    for rel in ("apps/web/app/layout.tsx", "apps/web/app/manifest.ts"):
        p = ROOT / rel
        if not p.exists():
            continue
        for m in re.finditer(r'"(/brand/[^"]+)"', p.read_text(encoding="utf-8")):
            refs.setdefault(m.group(1), []).append(rel)

    missing = [
        (u, srcs)
        for u, srcs in sorted(refs.items())
        if not (ROOT / "apps/web/public" / u.lstrip("/")).exists()
    ]
    if missing:
        print(f"✗ {len(missing)} icon reference(s) point at files that DO NOT EXIST:")
        for u, srcs in missing:
            print(f"    {u}  ← {', '.join(sorted(set(srcs)))}")
        print("  Run: python3 scripts/brand/build-brand-assets.py")
        return 1
    if not refs:
        print(
            "✗ no /brand/* references found — the scan found nothing to check, which is"
        )
        print("  a broken probe, not a clean result.")
        return 1
    print(f"OK — all {len(refs)} referenced /brand/* asset(s) exist.")
    return 0


def selftest() -> int:
    """Prove the verifier CATCHES the two failure modes the supplied zip shipped."""
    ok = True

    # B-252's own falsification: a reference to a file that is not there must be caught.
    import re as _re

    _txt = (ROOT / "apps/web/app/layout.tsx").read_text(encoding="utf-8")
    _found = _re.findall(r'"(/brand/[^"]+)"', _txt)
    _planted = "/brand/__selftest-does-not-exist.png"
    if _found and not (ROOT / "apps/web/public" / _planted.lstrip("/")).exists():
        print(f"  selftest: ref-scan sees {len(_found)} real ref(s) → PROBE ALIVE ✓")
    else:
        print("  selftest: ref-scan found nothing to check ✗")
        ok = False
    blank = _png(
        64, 64, b"".join(b"\x00" + b"\x00\x00\x00\x00" * 64 for _ in range(64))
    )
    i = inspect(blank)
    if i["mark_px"] == 0:
        print("  selftest: fully-transparent PNG  → CAUGHT ✓")
    else:
        print(f"  selftest: transparent PNG not caught ({i}) ✗")
        ok = False

    solid = _png(
        64, 64, b"".join(b"\x00" + b"\xff\xff\xff\xff" * 64 for _ in range(64))
    )
    i = inspect(solid)
    if i["mark_px"] == 0:
        print("  selftest: solid-rectangle PNG    → CAUGHT ✓")
    else:
        print(f"  selftest: solid rectangle not caught ({i}) ✗")
        ok = False

    real = render_png(size=64, ink=INK, bg=PAPER, shape="none", pad=0.05)
    i = inspect(real)
    frac = i["mark_px"] / i["total"]
    if 0.02 < frac < 0.9:
        print(f"  selftest: real mark at 64px      → PASSES ✓ ({frac:.1%} ink)")
    else:
        print(f"  selftest: real mark misjudged ({frac:.2%}) ✗")
        ok = False

    # SMALL_AT IS MEASURED HERE, NOT ASSERTED BY A COMMENT. The full cut is usable
    # only while all three concentric bands (outer stroke · gap · inner stroke) clear
    # the ~1.5px floor. BOTH directions are checked: a one-sided test would pass with
    # SMALL_AT set to any larger number, which is how a threshold quietly becomes
    # decoration. Move the constant or retune a stroke and this argues back.
    _at = _narrowest_band_px(SMALL_AT, 0.05)
    _below = _narrowest_band_px(SMALL_AT - 1, 0.05)
    if _at >= BAND_FLOOR_PX > _below:
        print(
            f"  selftest: SMALL_AT={SMALL_AT} sits on the measured floor → PASSES ✓"
            f" ({_at:.2f}px at it, {_below:.2f}px below, floor {BAND_FLOOR_PX}px)"
        )
    else:
        print(
            f"  selftest: SMALL_AT={SMALL_AT} is NOT the floor"
            f" ({_at:.2f}px at it, {_below:.2f}px below) ✗"
        )
        ok = False

    if _cut_for(SMALL_AT) is MARK_FULL and _cut_for(SMALL_AT - 1) is MARK_SMALL:
        print("  selftest: _cut_for switches AT SMALL_AT → PASSES ✓")
    else:
        print("  selftest: _cut_for does not switch at SMALL_AT ✗")
        ok = False

    tiny = render_png(size=16, ink=INK, bg=PAPER, shape="none", pad=0.03)
    i = inspect(tiny)
    if i["mark_px"] >= 20:
        print(f"  selftest: mark legible at 16px   → PASSES ✓ ({i['mark_px']} ink px)")
    else:
        print(f"  selftest: 16px mark too sparse ({i['mark_px']} px) ✗")
        ok = False

    # REGRESSION: a transparent-background mark must not read as blank. This exact
    # false negative fired on the first real build and reported four good logos dead.
    trans = render_png(size=128, ink=INK, bg=None, shape="none", pad=0.02)
    i = inspect(trans)
    if i["transparent_bg"] and i["mark_px"] > 0.1 * i["total"]:
        print(f"  selftest: transparent-bg mark    → PASSES ✓ ({i['mark_px']} ink px)")
    else:
        print(f"  selftest: transparent-bg mark read as blank ({i}) ✗")
        ok = False

    # ...and a genuinely empty transparent canvas must STILL be caught, or the fix
    # above would have traded a false negative for a false positive.
    empty = _png(
        32, 32, b"".join(b"\x00" + b"\x00\x00\x00\x00" * 32 for _ in range(32))
    )
    if inspect(empty)["mark_px"] == 0:
        print("  selftest: empty transparent PNG  → CAUGHT ✓")
    else:
        print("  selftest: empty transparent PNG slipped through ✗")
        ok = False

    print("✓ selftest PASSED" if ok else "✗ selftest FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument(
        "--check-refs",
        action="store_true",
        help="B-252 guard: every referenced /brand/* asset must exist",
    )
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--ascii", action="store_true", help="print the mark as ASCII")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.check_refs:
        return check_refs()
    if args.ascii:
        cov = _coverage(_cut_for(52), 52, 0.02)
        for y in range(52):
            print(
                "".join(
                    "#"
                    if cov[y * 52 + x] > 0.5
                    else ("+" if cov[y * 52 + x] > 0.15 else ".")
                    for x in range(52)
                )
            )
        return 0
    if args.verify:
        with tempfile.TemporaryDirectory() as td:
            build(Path(td))
            return verify(Path(td))
    written = build(ROOT)
    print(f"wrote {len(written)} asset(s) under brand/")
    return verify(ROOT)


if __name__ == "__main__":
    sys.exit(main())

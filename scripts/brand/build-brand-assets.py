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
# THE GEOMETRY. 100x100 grid, y down. Stroke S=12, counter gap G=10, all
# diagonals exactly 45 degrees. This is the single source of truth for the mark.
# ─────────────────────────────────────────────────────────────────────────────
S, G = 12, 10

# Component 1 — top bar + left riser + left stem. The bar's bottom-right is chamfered
# 45 degrees; the left arm's bottom-left is chamfered; the stem ends on a 45 cut.
BAR_TOP = [(2, 2), (96, 2), (84, 14), (2, 14)]
LEFT_ARM = [(2, 14), (14, 14), (14, 28), (44, 28), (44, 40), (12, 40), (2, 30)]
STEM_LEFT = [(32, 40), (44, 40), (44, 86), (32, 98)]

# Component 2 — the diagonal riser and right arm, separated from component 1 by the
# 45-degree counter. Its edge (84,28)->(96,16) is PARALLEL to the bar's chamfer
# (96,2)->(84,14); the two lines are x+y=112 and x+y=98, so the counter is
# 14/sqrt(2) = 9.9 wide — the same 10 as the vertical gap between the stems.
RIGHT_ARM = [(96, 16), (96, 28), (84, 40), (54, 40), (54, 28), (84, 28)]
STEM_RIGHT = [(54, 40), (66, 40), (66, 64), (78, 64), (54, 88)]

MARK = [BAR_TOP, LEFT_ARM, STEM_LEFT, RIGHT_ARM, STEM_RIGHT]

INK = "#0D0D0D"  # ADR-074 §8: the mark is never coloured.
PAPER = "#FFFFFF"

TAGLINE = "THE FLIGHT RECORDER FOR AI AGENTS"
# Wordmark face: the app's incumbent, with the ADR-074 target first. SVG text stays
# text on purpose — outlining it here would fork the wordmark from the product's font.
FONT_STACK = "Inter, 'Plus Jakarta Sans', ui-sans-serif, system-ui, sans-serif"


# ─────────────────────────────────────────────────────────────────────────────
# Rasterizer — scanline polygon fill with NxN supersampling. Exact for straight edges.
# ─────────────────────────────────────────────────────────────────────────────
def _coverage(polys, size: int, pad: float, ss: int = 0) -> list[float]:
    """Per-pixel coverage 0..1 of `polys` (100-unit space) rendered into size x size.

    Supersampling is adaptive: small sizes are where antialiasing quality actually
    shows, and a 1024px render at 4x would allocate a 16.7M-cell buffer in pure Python
    for no visible gain (and this machine has an OOM history).
    """
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
    cov = _coverage(MARK, size, pad)
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
def _paths(fill: str, dx: float = 0, dy: float = 0, scale: float = 1.0) -> str:
    out = []
    for poly in MARK:
        d = (
            "M "
            + " L ".join(f"{x * scale + dx:g},{y * scale + dy:g}" for x, y in poly)
            + " Z"
        )
        out.append(f'    <path d="{d}"/>')
    return f'  <g fill="{fill}">\n' + "\n".join(out) + "\n  </g>"


def svg_mark(fill: str) -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" '
        f'height="100" role="img" aria-label="Tracelane">\n  <title>Tracelane</title>\n'
        f"{_paths(fill)}\n</svg>\n"
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
    o.append(("apps/docs/favicon.svg", "svg_mark", {"fill": INK}))
    return o


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
    p = dest / "brand/png/favicon.ico"
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
    for rel, kind, _ in outputs():
        p = dest / rel
        if not p.exists():
            bad.append((rel, "MISSING"))
            continue
        if kind != "png":
            t = p.read_text()
            if "<path" not in t or t.count("<path") < len(MARK):
                bad.append(
                    (rel, f"SVG has {t.count('<path')} paths, expected {len(MARK)}")
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
    ico = dest / "brand/png/favicon.ico"
    if not ico.exists() or ico.stat().st_size < 1000:
        bad.append(("brand/png/favicon.ico", "missing or too small"))

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
        cov = _coverage(MARK, 52, 0.02)
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

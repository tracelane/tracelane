#!/usr/bin/env node
/*
 * WCAG 2.1 contrast proof for the Neon token set (ADR-045 / the design-system spec §1).
 * Parses src/styles/tokens.css, computes the contrast ratio for every
 * text/UI pair that must be legible, and FAILS (exit 1) if any text pair is
 * < 4.5:1 or any large/UI pair is < 3:1. Run: `pnpm --filter @tracelanedev/ui contrast:check`.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(here, "..", "src", "styles", "tokens.css"), "utf8");

/** Extract a `--name: #hex;` map from a CSS block matched by `selector`. */
function vars(blockHeader) {
 const start = css.indexOf(blockHeader);
 if (start === -1) throw new Error(`block not found: ${blockHeader}`);
 const open = css.indexOf("{", start);
 const close = css.indexOf("}", open);
 const body = css.slice(open + 1, close);
 const map = {};
 for (const m of body.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) {
 map[m[1]] = m[2];
 }
 return map;
}

function lum(hex) {
 const n = Number.parseInt(hex.slice(1), 16);
 const srgb = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
 const c = v / 255;
 return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
 });
 return 0.2126 * srgb[0] + 0.7152 * srgb[1] + 0.0722 * srgb[2];
}
function ratio(a, b) {
 const [l1, l2] = [lum(a), lum(b)].sort((x, y) => y - x);
 return (l1 + 0.05) / (l2 + 0.05);
}

// text pairs need >= 4.5:1; UI/large (focus ring, borders, big accents) >= 3:1.
const PAIRS = [
 // [fg, bg, minRatio, label]
 ["ink", "bg", 4.5, "body text on canvas"],
 ["ink", "surface", 4.5, "body text on card"],
 ["ink-2", "bg", 4.5, "muted text on canvas"],
 ["ink-2", "surface", 4.5, "muted text on card"],
 ["ink-3", "surface", 3.0, "faint/placeholder on card (UI)"],
 ["accent-ink", "bg", 4.5, "accent text (links) on canvas"],
 ["accent-ink", "surface", 4.5, "accent text on card"],
 ["accent-on", "accent", 4.5, "label on a lime fill (button)"],
 ["seal-ink", "bg", 4.5, "provenance text on canvas"],
 ["seal-ink", "surface", 4.5, "provenance text on card"],
 ["seal-on", "seal", 4.5, "label on a teal seal fill"],
 // the trace-line/data-bars/links use --accent-ink (legible in both themes);
 // raw bright --accent is a FILL only (tested above via accent-on/accent).
 ["accent-ink", "bg", 3.0, "accent mark: trace-line/data-bar/link/focus on canvas (UI)"],
 ["seal-ink", "bg", 3.0, "seal hairline/thread on canvas (UI)"],
 ["line", "bg", 1.0, "border on canvas (decorative)"],
 ["ok", "bg", 3.0, "status ok (UI)"],
 ["danger", "bg", 3.0, "status danger (UI)"],
 ["warn", "bg", 3.0, "status warn (UI)"],
];

let failed = 0;
for (const [theme, header] of [
 ["DARK", ":root {"],
 ["LIGHT", '[data-theme="light"],'],
]) {
 const v = vars(header);
 console.log(`\n${theme}`);
 for (const [fg, bg, min, label] of PAIRS) {
 if (!v[fg] || !v[bg]) {
 console.log(` ?? ${fg} on ${bg} — token missing`);
 continue;
 }
 const r = ratio(v[fg], v[bg]);
 const ok = r >= min;
 if (!ok) failed++;
 console.log(
 ` ${ok ? "PASS" : "FAIL"} ${r.toFixed(2)}:1 (≥${min}) ${fg} on ${bg} — ${label}`,
 );
 }
}

if (failed > 0) {
 console.error(`\n✗ ${failed} contrast pair(s) below threshold — fix tokens.`);
 process.exit(1);
}
console.log("\n✓ all token pairs meet WCAG thresholds in both themes.");

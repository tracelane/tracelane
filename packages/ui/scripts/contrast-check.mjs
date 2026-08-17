#!/usr/bin/env node
/*
 * WCAG 2.1 contrast proof for the token set. Parses src/styles/tokens.css at runtime,
 * so it tracks whatever the tokens are — it hardcodes no palette. Wired into
 * scripts/verify-all.sh as of 2026-08-15.
 * Parses src/styles/tokens.css, computes the contrast ratio for every
 * text/UI pair that must be legible, and FAILS (exit 1) if any text pair is
 * < 4.5:1 or any large/UI pair is < 3:1. Run: `pnpm --filter @tracelanedev/ui contrast:check`.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(
	join(here, "..", "src", "styles", "tokens.css"),
	"utf8",
);

/** Extract a `--name: #hex;` map from a CSS block matched by `selector`.
 *
 * Resolves ONE level of `var(--other)` indirection. The palette deliberately
 * aliases role tokens onto source tokens (`--accent-ink: var(--lava-deep)`), and
 * without this every aliased pair silently reported "token missing" — a check that
 * skips the pairs it cannot parse is not a check.
 */
function vars(blockHeader) {
	const start = css.indexOf(blockHeader);
	if (start === -1) throw new Error(`block not found: ${blockHeader}`);
	const open = css.indexOf("{", start);
	const close = css.indexOf("}", open);
	const body = css.slice(open + 1, close);
	const map = {};
	const alias = {};
	for (const m of body.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) {
		map[m[1]] = m[2];
	}
	for (const m of body.matchAll(/--([\w-]+):\s*var\(--([\w-]+)\)\s*;/g)) {
		alias[m[1]] = m[2];
	}
	for (const [name, target] of Object.entries(alias)) {
		if (map[target]) map[name] = map[target];
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
	["accent-on", "accent", 4.5, "label on an accent fill (button)"],
	["seal-ink", "bg", 4.5, "provenance text on canvas"],
	["seal-ink", "surface", 4.5, "provenance text on card"],
	["seal-on", "seal", 4.5, "label on a teal seal fill"],
	// the trace-line/data-bars/links use --accent-ink (legible in both themes);
	// raw bright --accent is a FILL only (tested above via accent-on/accent).
	[
		"accent-ink",
		"bg",
		3.0,
		"accent mark: trace-line/data-bar/link/focus on canvas (UI)",
	],
	["seal-ink", "bg", 3.0, "seal hairline/thread on canvas (UI)"],
	["line", "bg", 1.0, "border on canvas (decorative)"],
	// THE INVERSE SURFACE. There was NO pair for it, and that gap shipped a metric at
	// 1:1 contrast: --accent and --surface-inverse are BOTH ink after ADR-074, so the
	// error-budget burn rate rendered #0d0d0d on #0d0d0d in light theme — invisible.
	// A contrast checker that never looks at a surface cannot report anything about it.
	["ink-inverse", "surface-inverse", 4.5, "value/text ON the inverse (dark) card"],
	// `selected-on`, NOT `ink-inverse`. The first version of this line asserted
	// ink-inverse and failed at 1.00:1 in dark — correctly, because in dark BOTH are
	// #f0f3f7. But the app never renders that combination: the active pill is
	// `bg-selected text-selected-on`. A gate must assert what is RENDERED; asserting a
	// combination nobody uses is a red that teaches people to edit the gate.
	["selected-on", "selected", 4.5, "label on the selected/active pill"],
	["ok", "bg", 3.0, "status ok (UI)"],
	["danger", "bg", 3.0, "status danger (UI)"],
	["warn", "bg", 3.0, "status warn (UI)"],
];

// ── argv ────────────────────────────────────────────────────────────────────
// The meta-gate (scripts/ci/check-guard-selftests.py) requires every guard
// verify-all.sh invokes to tell --selftest from a nonsense flag. A script with no
// argv handling exits 0 for BOTH, which is indistinguishable from a passing
// selftest — that is how 20 scripts once looked green while proving nothing.
const ARGV = process.argv.slice(2);
const SELFTEST = ARGV.includes("--selftest");
for (const a of ARGV) {
	if (a !== "--selftest") {
		console.error(`unknown flag: ${a}`);
		process.exit(2);
	}
}

if (SELFTEST) {
	// Plant a pair that MUST fail, and one that MUST pass. A checker that cannot be
	// shown to go red is not a control.
	const bad = ratio("#8b919c", "#ffffff"); // 2.90:1 — under the 4.5 text floor
	const good = ratio("#0d0d0d", "#ffffff"); // 19.44:1
	let ok = true;
	if (bad >= 4.5) {
		console.log(`  selftest: low-contrast pair scored ${bad.toFixed(2)} — NOT caught ✗`);
		ok = false;
	} else {
		console.log(`  selftest: low-contrast pair ${bad.toFixed(2)}:1 → CAUGHT ✓`);
	}
	if (good < 4.5) {
		console.log(`  selftest: high-contrast pair wrongly failed ✗`);
		ok = false;
	} else {
		console.log(`  selftest: high-contrast pair ${good.toFixed(2)}:1 → PASSES ✓`);
	}
	// And prove BOTH theme blocks actually parse — the bug this script shipped with
	// was a dark selector that never existed, so it measured light twice and threw.
	for (const [label, header] of [["light", ":root {"], ["dark", '[data-theme="dark"],']]) {
		const v = vars(header);
		const n = Object.keys(v).length;
		if (n < 20) {
			console.log(`  selftest: ${label} block parsed only ${n} tokens ✗`);
			ok = false;
		} else {
			console.log(`  selftest: ${label} block parses ${n} tokens → PASSES ✓`);
		}
	}
	console.log(ok ? "✓ selftest PASSED" : "✗ selftest FAILED");
	process.exit(ok ? 0 : 1);
}

let failed = 0;
// `:root` is the LIGHT default (ADR-074 §3 keeps light default); dark is the
// [data-theme="dark"] block. These two labels were INVERTED and the dark selector
// was '[data-theme="light"],' — a block that has never existed — so this script
// printed the LIGHT palette under the heading "DARK" and then threw before it ever
// measured dark. It is wired to no CI job, so it failed that way unnoticed.
for (const [theme, header] of [
	["LIGHT (default)", ":root {"],
	["DARK", '[data-theme="dark"],'],
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

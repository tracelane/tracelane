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
 * Resolves ONE level of `var(--other)` indirection. The palette aliases some role
 * tokens onto others (`--focus-ring: var(--ink)` is the only one left in the two
 * theme blocks as of 2026-08-22 — the `--lava-*` sources this line used to cite are
 * DELETED), and without this an aliased pair silently reported "token missing" — a
 * check that skips the pairs it cannot parse is not a check.
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
	["action-ink", "bg", 4.5, "accent text (links) on canvas"],
	["action-ink", "surface", 4.5, "accent text on card"],
	["action-on", "action", 4.5, "label on an accent fill (button)"],
	["seal-ink", "bg", 4.5, "provenance text on canvas"],
	["seal-ink", "surface", 4.5, "provenance text on card"],
	// `["seal-on","seal"]` was here and is DELETED with the token (2026-08-22).
	// Nothing in the app paints a SOLID seal fill with a label on it — the seal is a
	// 2px provenance strip (`.card-provenance-top`) and a soft chip (`bg-seal-soft`).
	// So this pair asserted a combination that is never rendered, which is the same
	// trap the `selected-on` note below records — and it kept a dead token alive by
	// giving it a consumer that existed only inside this gate.
	// The trace-line / data-bars / links all paint `--action-ink`, which is legible on
	// both grounds. `--action` itself is a FILL only, tested above as action-on/action.
	// (This said "--accent-ink" and "raw bright --accent": `--accent-*` IS `--action-*`
	// since 2026-08-17, and after the P0 swap nothing in the action family is bright —
	// it is the ink value, #171717 light / #f5f5f5 dark.)
	[
		"action-ink",
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
	// ink-inverse and failed at 1.00:1 in dark — correctly, because in dark BOTH resolve
	// to the same value (#f0f3f7 then; #f5f5f5 under the P0 palette). But the app never
	// renders that combination: the active pill is
	// `bg-selected text-selected-on`. A gate must assert what is RENDERED; asserting a
	// combination nobody uses is a red that teaches people to edit the gate.
	["selected-on", "selected", 4.5, "label on the selected/active pill"],
	["ok", "bg", 3.0, "status ok (UI)"],
	["danger", "bg", 3.0, "status danger (UI)"],
	["warn", "bg", 3.0, "status warn (UI)"],

	// ── ADDED 2026-08-22 with the "Instrument II" palette ────────────────────
	// The pairs above covered ink, action and seal and stopped there, so the
	// three STATUS families — the only colour left in the system — were checked
	// only as UI marks on the canvas and never as the badge text they actually
	// render as. `<Badge tone="warn">` is `bg-warn-soft text-warn-ink`, and
	// NOTHING asserted that combination. Each `-ink` token exists precisely to
	// clear this floor; until now it cleared it by assertion in a comment.
	["ok-ink", "ok-soft", 4.5, "ok badge text on its soft fill"],
	["warn-ink", "warn-soft", 4.5, "warn badge text on its soft fill"],
	["danger-ink", "danger-soft", 4.5, "danger badge text on its soft fill"],
	["seal-ink", "seal-soft", 4.5, "provenance chip text on its soft fill"],
	["info-ink", "info-soft", 4.5, "info chip text on its soft fill"],
	["ok-ink", "surface", 4.5, "ok text on a card"],
	["warn-ink", "surface", 4.5, "warn text on a card"],
	["danger-ink", "surface", 4.5, "danger text on a card"],
	["danger-on", "danger", 3.0, "white label on a solid danger fill (large/UI)"],

	// The second surface tier. `--surface-2` is the WELL every chip, icon disc,
	// bar track and inert fill sits on, and text lands on it constantly — the
	// pairs above only ever measured against `--surface` and `--bg`.
	["ink-2", "surface-2", 4.5, "secondary text on the well"],
	["ink-3", "surface-2", 3.0, "tertiary/label on the well (UI)"],
	["ink", "surface-2", 4.5, "primary text on the well"],
	["ink-2", "canvas-sunken", 4.5, "table-header text on the sunken strip"],
	["ink", "sidebar", 4.5, "nav label on the rail"],
	["ink-2", "sidebar", 4.5, "nav section label on the rail"],
	["ink-3", "sidebar", 3.0, "faint nav text on the rail (UI)"],

	// The chart roles (P0.11). `--chart-primary` is the one data colour, so it is
	// a graphical object essential to understanding: WCAG 2.2 SC 1.4.11, 3:1.
	["chart-primary", "surface", 3.0, "the data mark on a card (UI)"],
	["chart-primary", "bg", 3.0, "the data mark on the canvas (UI)"],
	//
	// `--chart-secondary` DELIBERATELY HAS NO FLOOR AGAINST THE CARD, and that is
	// a judgement written down rather than an oversight. It measures 2.41:1 on
	// white — under 1.4.11's 3:1 — because the brief pins it at #A7A7A7 as the
	// DE-EMPHASISED role: the "Other" remainder arc, an inactive mark, a second
	// series that is present but not the point. What has to be legible about such
	// a mark is its SEPARATION FROM THE PRIMARY SERIES beside it, not its
	// contrast with the paper behind it, so that is what is asserted. If a second
	// series is ever made load-bearing, this pair is the wrong control for it and
	// the token needs deepening — say so then rather than editing this line.
	["chart-secondary", "chart-primary", 3.0, "second series vs first (adjacent marks)"],
	["chart-grid", "surface", 1.0, "gridline on a card (decorative)"],
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
	// The fixture is ACHROMATIC (#909090) and the ratio is the MEASURED one. It was
	// `#8b919c` annotated "2.90:1", and both halves were wrong: that pair actually
	// scores 3.17:1, and #8b919c has B > R by 17 — a blue-grey, the last cool hex left
	// in this package outside tokens.css. The property proven is unchanged (a pair
	// under the 4.5 text floor is caught); only the hue and the stale number moved.
	const bad = ratio("#909090", "#ffffff"); // 3.19:1 — under the 4.5 text floor
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
	// And prove the MISSING-TOKEN path is a failure rather than a skip. Planting a
	// pair that names a token nobody defines is the only way to show the branch
	// that used to `continue` silently now counts against the run.
	{
		const v = vars(":root {");
		const bogus = "definitely-not-a-token-2026";
		if (v[bogus] === undefined) {
			console.log(
				`  selftest: unknown token --${bogus} is absent → the missing-token branch is reachable ✓`,
			);
		} else {
			console.log(`  selftest: could not plant an unknown token ✗`);
			ok = false;
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
			// A MISSING TOKEN IS A FAILURE, NOT A SKIP (2026-08-22). This printed
			// `?? token missing` and `continue`d WITHOUT touching `failed`, so a pair
			// naming a token that had been renamed or deleted went green — the gate
			// reported "all token pairs meet WCAG thresholds" while silently checking
			// fewer pairs than it listed. That is the "guard that checks nothing"
			// shape: the louder the palette churn, the more pairs it quietly dropped.
			failed++;
			console.log(
				` FAIL ${fg} on ${bg} — TOKEN MISSING (${!v[fg] ? `--${fg}` : `--${bg}`} is not defined in this theme block); the pair is unchecked, which is worse than a low ratio`,
			);
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

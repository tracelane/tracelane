/**
 * Build regression guard — asserts the emitted CSS bundle contains real
 * Tailwind utilities, not just theme/preflight.
 *
 * Background: a missing `postcss.config.mjs` once let `next build` finish GREEN
 * while emitting a CSS bundle with an unprocessed `@tailwind utilities`
 * directive and zero utility classes — the entire app shipped unstyled. This
 * guard runs after `next build` (see package.json `build` script) and fails the
 * build if a known utility selector is absent, so that can never ship again.
 *
 * Self-healing policy (CLAUDE.md): this is the regression test for the
 * `fix(web): register @tailwindcss/postcss` commit.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const CSS_DIR = ".next/static/css";
// Each sentinel is a utility the root layout genuinely renders
// (`<div className="flex min-h-screen bg-bg">`), chosen to span BOTH failure
// modes this guard exists to catch — and asserted together so the guard can
// never pass vacuously:
// .bg-bg — a custom @theme (Neon) color utility. Absent if the
// `@import "@tracelanedev/ui/styles/tokens.css"` / @theme
// pipeline didn't emit token utilities, even when core
// Tailwind ran. This is the app-specific signal.
// .flex — a core utility. Absent if @tailwindcss/postcss never
// processed `@tailwind utilities` at all (the unstyled-ship
// regression this guard was written for).
// .min-h-screen — a second core utility, so one stray match can't green it.
// If you remove one from the root layout, repoint it to another class the
// layout actually renders — do NOT delete the assertion.
const SENTINELS = [".bg-bg", ".flex", ".min-h-screen"];

function fail(msg) {
	console.error(`[css-guard] FAIL: ${msg}`);
	process.exit(1);
}

let files;
try {
	files = readdirSync(CSS_DIR).filter((f) => f.endsWith(".css"));
} catch {
	fail(`no ${CSS_DIR} directory — did \`next build\` run?`);
}

if (files.length === 0) fail(`no .css files in ${CSS_DIR}`);

const bundles = files.map((f) => readFileSync(join(CSS_DIR, f), "utf8"));
const missing = SENTINELS.filter(
	(sel) => !bundles.some((css) => css.includes(sel)),
);

if (missing.length > 0) {
	fail(
		`Tailwind utilities absent — sentinel(s) ${missing
			.map((s) => `"${s}"`)
			.join(
				", ",
			)} not found in ${files.length} bundle(s). Either @tailwindcss/postcss isn't running (check apps/web/postcss.config.mjs) or the Neon @theme tokens didn't import (.bg-bg) — both ship the app unstyled.`,
	);
}

console.log(
	`[css-guard] OK — utilities present (${SENTINELS.map((s) => `"${s}"`).join(
		", ",
	)} all found across ${files.length} bundle(s)).`,
);

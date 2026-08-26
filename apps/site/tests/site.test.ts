/**
 * apps/site tests — the consolidation's own gate.
 *
 * WHY THIS FILE EXISTS AT ALL. Before consolidation the site repo had **no CI, no tests
 * and no workflows** — `.github/` held CODEOWNERS and dependabot.yml and nothing else
 * (B-142a). Moving the site into the monorepo only helps if something here actually runs:
 * `pnpm --recursive` will call `test` in every workspace package, so an `apps/site` with
 * no `test` script would have been consolidated and STILL ungated — a silent CLASS-1,
 * and the exact failure mode of "we moved it, so it's covered".
 *
 * Every assertion below is a regression for a defect that was REAL on 2026-08-16:
 *  · /pricing 404'd live while ADR-074 §10 listed it as must-have scope
 *  · three indexed URLs would have become 404s when their pages left scope
 *  · www served 200 duplicate content while README-DEPLOY claimed a `_redirects` 301
 *    (`_redirects` is a Pages feature and this is a Worker — it was never running)
 *  · the CSP's `form-action 'self'` would have silently killed a Polar checkout
 *  · the security page claimed trufflehog runs in CI (it does not) and an SSRF
 *    "redirect cap 3" (redirects are disabled entirely — the truth is stronger)
 *  · the site carried a FOURTH palette
 *
 * Assertions run against `dist/` — the artifact that ships — not the source, wherever
 * that is possible.
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { test, describe } from "node:test";
import { resolveRedirect } from "../functions/api/notify.ts";

const SITE = join(import.meta.dirname, "..");
const DIST = join(SITE, "dist");

const built = existsSync(DIST);
const skip = built ? undefined : "run `pnpm --filter @tracelanedev/site build` first";

function distCss(): string {
	const dir = join(DIST, "_astro");
	return readdirSync(dir)
		.filter((f) => f.endsWith(".css"))
		.map((f) => readFileSync(join(dir, f), "utf8"))
		.join("\n");
}

describe("redirects — retired URLs keep their link equity", () => {
	const url = (p: string, host = "tracelane.dev") =>
		new URL(`https://${host}${p}`);

	test("the three out-of-scope indexed URLs 301 instead of 404", () => {
		// ADR-074 §10 drops changelog, docs and the competitor page from scope. They
		// were in the live sitemap; dropping the pages without these would have turned
		// three indexed URLs into 404s.
		assert.equal(resolveRedirect("tracelane.dev", url("/changelog")), "https://tracelane.dev/");
		assert.equal(resolveRedirect("tracelane.dev", url("/vs/langsmith-engine")), "https://tracelane.dev/");
		assert.equal(resolveRedirect("tracelane.dev", url("/docs")), "https://docs.tracelane.dev/");
	});

	test("a trailing slash redirects identically — the sitemap used that form", () => {
		assert.equal(resolveRedirect("tracelane.dev", url("/changelog/")), "https://tracelane.dev/");
	});

	test("www 301s to the apex, preserving the path", () => {
		// Verified live 2026-08-15: www returned 200 with ZERO redirects while
		// README-DEPLOY.md claimed a `_redirects` 301. It is a Worker, not Pages.
		assert.equal(
			resolveRedirect("www.tracelane.dev", url("/security", "www.tracelane.dev")),
			"https://tracelane.dev/security",
		);
	});

	test("a live in-scope page is NOT redirected", () => {
		// Both halves, or the test only proves the function returns strings.
		assert.equal(resolveRedirect("tracelane.dev", url("/pricing")), null);
		assert.equal(resolveRedirect("tracelane.dev", url("/")), null);
		assert.equal(resolveRedirect("tracelane.dev", url("/security")), null);
	});
});

describe("built output", { skip }, () => {
	test("/pricing is a real page — it 404'd before 2026-08-16", () => {
		assert.ok(
			existsSync(join(DIST, "pricing", "index.html")),
			"/pricing/index.html missing — the route ADR-074 §10 calls must-have",
		);
	});

	test("every must-have page in §10 scope is built", () => {
		for (const p of ["index.html", "pricing/index.html", "security/index.html", "privacy/index.html", "terms/index.html"]) {
			assert.ok(existsSync(join(DIST, p)), `missing ${p}`);
		}
	});

	test("pricing renders the SAME ladder as the homepage anchor", () => {
		// One component, two surfaces. If they ever diverge, a price is being maintained
		// in two places — the drift this repo already tracks a parallel-update set for.
		const home = readFileSync(join(DIST, "index.html"), "utf8");
		const pricing = readFileSync(join(DIST, "pricing", "index.html"), "utf8");
		for (const tier of ["$59", "$249", "$899", "$2,999+", "+$999"]) {
			assert.ok(home.includes(tier), `homepage lost ${tier}`);
			assert.ok(pricing.includes(tier), `/pricing lost ${tier}`);
		}
	});

	test("the retired 'Soft Gradient' palette is gone from the shipped CSS", () => {
		const css = distCss();
		for (const hex of ["e4724a", "cf5a33", "c0492a", "b6cfd5", "fbebe0", "147d5c", "fdf051"]) {
			assert.ok(!css.toLowerCase().includes(hex), `retired colour #${hex} still ships`);
		}
	});

	test("ADR-074 chrome is what actually ships", () => {
		// READ THE TOKENS, DO NOT HARDCODE THEM. This asserted a literal list of hexes
		// and went red the moment the founder asked for darker muted ink — not because
		// the site broke, but because the test was a SECOND copy of the palette. A test
		// that has to be edited every time the design changes is a maintenance tax that
		// teaches people to edit tests, so it now derives its expectation from the one
		// source of truth (`tokens.css`) and proves those values reached the artifact.
		const tokens = readFileSync(
			join(SITE, "..", "..", "packages", "ui", "src", "styles", "tokens.css"),
			"utf8",
		);
		// Slice the LIGHT block. `[data-theme="dark"]` also appears in a COMMENT above
		// `:root`, so searching from index 0 found that first and produced an EMPTY
		// slice — every lookup then failed with "token not found", which reads like a
		// missing token rather than a broken slice. Search for the dark SELECTOR, and
		// only after the `:root` offset.
		const rootAt = tokens.indexOf(":root {");
		const darkAt = tokens.indexOf('[data-theme="dark"],', rootAt);
		assert.ok(rootAt >= 0 && darkAt > rootAt, "could not slice the light token block");
		const light = tokens.slice(rootAt, darkAt);
		const pick = (name: string) => {
			const m = new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`).exec(light);
			assert.ok(m, `token --${name} not found in tokens.css`);
			return (m?.[1] ?? "").toLowerCase();
		};
		const css = distCss().toLowerCase();
		for (const name of ["ink", "ink-2", "ink-3", "line", "ok"]) {
			const hex = pick(name);
			assert.ok(
				css.includes(hex.slice(1)),
				`--${name} (${hex}) is defined in tokens.css but did not reach the shipped CSS`,
			);
		}
	});

	test("marketing density survives the app token import (§2)", () => {
		// tokens.css sets `body { font-size: 12.5px }` for the app's 4px grid. §2 is
		// explicit that averaging the two densities is how the app ends up unusable —
		// so marketing must re-assert 16px, and this proves the override actually won.
		assert.match(distCss(), /font-size:\s*16px/);
	});
});

describe("honesty + security headers", () => {
	test("CSP allows a Polar checkout POST — form-action killed it silently before", () => {
		// PARSE THE DIRECTIVE, DO NOT GREP THE FILE. The first version of this matched
		// /form-action[^;]*polar\.sh/ against the whole file and passed even with the CSP
		// reverted to `form-action 'self'` — because the COMMENT above the header says
		// "form-action allows polar.sh DELIBERATELY". My own explanation defeated my own
		// assertion. Third instance of that failure in one session; the fix is always to
		// match the CONSTRUCTION (here: the actual header line, comments stripped).
		const csp = readFileSync(join(SITE, "public", "_headers"), "utf8")
			.split("\n")
			.filter((l) => !l.trimStart().startsWith("#"))
			.find((l) => l.includes("Content-Security-Policy:"));
		assert.ok(csp, "no Content-Security-Policy header found");
		const formAction = /form-action ([^;]*)/.exec(csp);
		assert.ok(formAction, "CSP has no form-action directive");
		assert.match(
			formAction[1] ?? "",
			/polar\.sh/,
			"form-action does not allow polar.sh — a checkout POST will be blocked by the "
				+ "browser with no error and no server log (B-129)",
		);
	});

	test("the security page makes no claim the code does not support", () => {
		const page = readFileSync(join(SITE, "src", "pages", "security.astro"), "utf8");
		// trufflehog appears in ZERO workflows; the claim said "every commit".
		assert.ok(!/trufflehog/i.test(page), "security page claims trufflehog runs in CI");
		// Redirects are DISABLED on the hardened client, not capped at 3.
		assert.ok(!/redirect cap 3/i.test(page), "security page claims an SSRF redirect cap of 3");
	});

	test("the copy lock holds: tamper-EVIDENT, never tamper-proof", () => {
		for (const f of readdirSync(join(SITE, "src", "pages"))) {
			if (!f.endsWith(".astro")) continue;
			const s = readFileSync(join(SITE, "src", "pages", f), "utf8");
			assert.ok(!/tamper-proof/i.test(s), `${f} says "tamper-proof"`);
		}
	});
});

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
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { resolveRedirect, serveRange } from "../functions/api/notify.ts";
import { LADDER, formatPrice, plan } from "../src/lib/plans.ts";

const SITE = join(import.meta.dirname, "..");
const DIST = join(SITE, "dist");

const built = existsSync(DIST);
const skip = built
	? undefined
	: "run `pnpm --filter @tracelanedev/site build` first";

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

	test("two out-of-scope indexed URLs 301 instead of 404", () => {
		// ADR-074 §10 originally dropped changelog, docs and the competitor page from
		// scope. /changelog was reinstated as a live page on 2026-09-07 (founder
		// request — see the supersession note in ADR-074 §10); the remaining two
		// out-of-scope indexed URLs still redirect so they keep their link equity.
		assert.equal(
			resolveRedirect("tracelane.dev", url("/vs/langsmith-engine")),
			"https://tracelane.dev/",
		);
		assert.equal(
			resolveRedirect("tracelane.dev", url("/docs")),
			"https://docs.tracelane.dev/",
		);
	});

	test("/changelog is NOT redirected — reinstated as a live page 2026-09-07", () => {
		// Both the canonical and trailing-slash forms must resolve (not redirect),
		// or a visitor arriving at the sitemap URL gets bounced to the homepage.
		assert.equal(resolveRedirect("tracelane.dev", url("/changelog")), null);
		assert.equal(resolveRedirect("tracelane.dev", url("/changelog/")), null);
	});

	test("the retired /product/<section> pages 301 to their section on /product (SITE-04)", () => {
		for (const s of ["gateway", "observability", "audit", "evals"]) {
			assert.equal(
				resolveRedirect("tracelane.dev", url(`/product/${s}`)),
				`https://tracelane.dev/product#${s}`,
			);
			assert.equal(
				resolveRedirect("tracelane.dev", url(`/product/${s}/`)),
				`https://tracelane.dev/product#${s}`,
			);
		}
		// The one page itself must NOT redirect, or the 301s would loop.
		assert.equal(resolveRedirect("tracelane.dev", url("/product")), null);
		assert.equal(resolveRedirect("tracelane.dev", url("/product/")), null);
	});

	test("www 301s to the apex, preserving the path", () => {
		// Verified live 2026-08-15: www returned 200 with ZERO redirects while
		// README-DEPLOY.md claimed a `_redirects` 301. It is a Worker, not Pages.
		assert.equal(
			resolveRedirect(
				"www.tracelane.dev",
				url("/security", "www.tracelane.dev"),
			),
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

	test("/changelog is a real page — reinstated 2026-09-07", () => {
		// /changelog redirected to / until 2026-09-07 (founder request). This proves
		// the page actually built — not just that the redirect was removed.
		assert.ok(
			existsSync(join(DIST, "changelog", "index.html")),
			"/changelog/index.html missing — the page was reinstated from a redirect",
		);
	});

	/**
	 * `sr-only` ON A TABLE-DISPLAY ELEMENT BLOWS OUT THE MOBILE PAGE WIDTH.
	 *
	 * REAL, 2026-09-09. `index.astro` carried `<table class="sr-only">` for the
	 * benchmark numbers. A table's used width is decided by its auto table
	 * layout, so `sr-only`'s `width: 1px` is a suggestion it ignores — the table
	 * laid out at 938px and, being absolutely positioned, pushed the document's
	 * scrollable width to 954px on a 390px phone. `html, body { overflow-x: clip }`
	 * hid that from a desktop browser (`documentElement.scrollWidth` read 390),
	 * but iOS Safari derives its MINIMUM ZOOM SCALE from the content width: the
	 * live page pinch-zoomed out to show the content in the left 41% with 564px
	 * of white beside it. Measured with the clip disabled, before: 954. After
	 * wrapping the table in `<div class="sr-only">`: 390.
	 *
	 * A block wrapper has no such exemption, so the RULE is "sr-only goes on the
	 * wrapper, never on the table". `changelog.astro` already did it correctly —
	 * the tree held both patterns, which is how the wrong one comes back.
	 *
	 * The check is a string scan, and its honest limit is that it proves the
	 * CLASS is absent, not that the page is 390px wide — only a browser can
	 * prove the width, and this suite has none.
	 */
	test("no `sr-only` sits directly on a table-display element", () => {
		// Both directions, in the assertion itself: the planted line must be
		// caught, or a green result below means nothing.
		const offenders = (html: string) =>
			[
				...html.matchAll(
					/<(table|thead|tbody|tfoot|tr)\b[^>]*\bclass="[^"]*\bsr-only\b[^"]*"/gi,
				),
			].map((m) => m[0]);

		assert.equal(
			offenders('<p class="sr-only">fine</p><table class="sr-only">').length,
			1,
			"the scanner cannot see the defect it exists to catch",
		);

		for (const page of [
			"index.html",
			"changelog/index.html",
			"pricing/index.html",
			"security/index.html",
			"privacy/index.html",
			"terms/index.html",
		]) {
			const file = join(DIST, page);
			if (!existsSync(file)) continue;
			const found = offenders(readFileSync(file, "utf8"));
			assert.equal(
				found.length,
				0,
				`${page}: sr-only is on a table element (${found[0]}). It does not ` +
					'collapse to 1px — wrap the table in <div class="sr-only"> instead.',
			);
		}
	});

	test("every must-have page in §10 scope is built", () => {
		for (const p of [
			"index.html",
			"pricing/index.html",
			"security/index.html",
			"privacy/index.html",
			"terms/index.html",
		]) {
			assert.ok(existsSync(join(DIST, p)), `missing ${p}`);
		}
	});

	test("pricing renders the SAME ladder as the homepage anchor, straight from plans.v3.json", () => {
		// One component, two surfaces. If they ever diverge, a price is being maintained
		// in two places — the drift this repo already tracks a parallel-update set for.
		// ADR-076: derived from apps/web/db/plans.v3.json via src/lib/plans.ts, never a
		// literal copy of the numbers (`.claude/rules/reference-tables.md`).
		const home = readFileSync(join(DIST, "index.html"), "utf8");
		const pricing = readFileSync(join(DIST, "pricing", "index.html"), "utf8");
		for (const key of LADDER) {
			if (key === "free_v1") continue; // Free renders "$0", too common a substring to assert usefully
			const row = plan(key);
			const price = formatPrice(row, "month");
			const needle = `${price.fromLabel ? "from " : ""}${price.amount}`;
			assert.ok(home.includes(needle), `homepage lost ${row.name}'s ${needle}`);
			assert.ok(
				pricing.includes(needle),
				`/pricing lost ${row.name}'s ${needle}`,
			);
		}
	});

	test("no retired pricing figure ships in the built HTML (ADR-076)", () => {
		const home = readFileSync(join(DIST, "index.html"), "utf8");
		const pricing = readFileSync(join(DIST, "pricing", "index.html"), "utf8");
		for (const retired of [
			"$59",
			"$249",
			"$899",
			"$2,999",
			"150K traces",
			"$1.20",
			"per 10K",
		]) {
			assert.ok(
				!home.includes(retired),
				`homepage still ships retired figure ${retired}`,
			);
			assert.ok(
				!pricing.includes(retired),
				`/pricing still ships retired figure ${retired}`,
			);
		}
	});

	test("the retired 'Soft Gradient' palette is gone from the shipped CSS", () => {
		const css = distCss();
		for (const hex of [
			"e4724a",
			"cf5a33",
			"c0492a",
			"b6cfd5",
			"fbebe0",
			"147d5c",
			"fdf051",
		]) {
			assert.ok(
				!css.toLowerCase().includes(hex),
				`retired colour #${hex} still ships`,
			);
		}
	});

	test("the shared app palette is what actually ships", () => {
		// READ THE TOKENS, DO NOT HARDCODE THEM. This asserted a literal list of hexes
		// and went red the moment the founder asked for darker muted ink — not because
		// the site broke, but because the test was a SECOND copy of the palette. A test
		// that has to be edited every time the design changes is a maintenance tax that
		// teaches people to edit tests, so it derives its expectation from the ONE
		// source of truth (`packages/ui/src/styles/tokens.css`, imported by
		// `global.css` — the site's own `tokens.site.css` fork was deleted 2026-09-04,
		// founder ruling: the site shares ONE palette with the app) and proves those
		// values reached the artifact.
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
		assert.ok(
			rootAt >= 0 && darkAt > rootAt,
			"could not slice the light token block",
		);
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
			"form-action does not allow polar.sh — a checkout POST will be blocked by the " +
				"browser with no error and no server log (B-129)",
		);
	});

	test("the security page makes no claim the code does not support", () => {
		const page = readFileSync(
			join(SITE, "src", "pages", "security.astro"),
			"utf8",
		);
		// trufflehog appears in ZERO workflows; the claim said "every commit".
		assert.ok(
			!/trufflehog/i.test(page),
			"security page claims trufflehog runs in CI",
		);
		// Redirects are DISABLED on the hardened client, not capped at 3.
		assert.ok(
			!/redirect cap 3/i.test(page),
			"security page claims an SSRF redirect cap of 3",
		);
	});

	test("the copy lock holds: tamper-EVIDENT, never tamper-proof", () => {
		for (const f of readdirSync(join(SITE, "src", "pages"))) {
			if (!f.endsWith(".astro")) continue;
			const s = readFileSync(join(SITE, "src", "pages", f), "utf8");
			assert.ok(!/tamper-proof/i.test(s), `${f} says "tamper-proof"`);
		}
	});
});

// B-588 (2026-09-27): the static-asset handler answers a Range request with 200 and the
// whole file, and Safari / iOS will not play an mp4 served without byte ranges. The
// Worker answers .mp4 itself; these pin the RFC 9110 shapes it must return.
describe("video byte ranges (B-588)", () => {
	const body = new Uint8Array(5000).map((_, i) => i % 251);
	const asset = () =>
		new Response(body, { headers: { "content-type": "video/mp4" } });
	const req = (range?: string, method = "GET") =>
		new Request("https://tracelane.dev/film.mp4", {
			method,
			headers: range ? { range } : {},
		});

	test("a bounded range is a 206 with exactly those bytes", async () => {
		const r = await serveRange(req("bytes=0-1023"), asset());
		assert.equal(r.status, 206);
		assert.equal(r.headers.get("content-range"), "bytes 0-1023/5000");
		assert.equal(r.headers.get("content-length"), "1024");
		assert.equal(r.headers.get("accept-ranges"), "bytes");
		const got = new Uint8Array(await r.arrayBuffer());
		assert.equal(got.length, 1024);
		assert.equal(got[1000], body[1000]);
	});
	test("an open range runs to the end; a suffix range takes the last N", async () => {
		const open = await serveRange(req("bytes=4990-"), asset());
		assert.equal(open.headers.get("content-range"), "bytes 4990-4999/5000");
		const suffix = await serveRange(req("bytes=-100"), asset());
		assert.equal(suffix.headers.get("content-range"), "bytes 4900-4999/5000");
		assert.equal((await suffix.arrayBuffer()).byteLength, 100);
	});
	test("an end past the file is clamped, a start past it is 416", async () => {
		const clamped = await serveRange(req("bytes=4000-99999"), asset());
		assert.equal(clamped.headers.get("content-range"), "bytes 4000-4999/5000");
		const bad = await serveRange(req("bytes=6000-"), asset());
		assert.equal(bad.status, 416);
		assert.equal(bad.headers.get("content-range"), "bytes */5000");
	});
	test("no Range is a 200 that advertises ranges; HEAD carries no body", async () => {
		const full = await serveRange(req(), asset());
		assert.equal(full.status, 200);
		assert.equal(full.headers.get("accept-ranges"), "bytes");
		assert.equal((await full.arrayBuffer()).byteLength, 5000);
		const head = await serveRange(req("bytes=0-9", "HEAD"), asset());
		assert.equal(head.status, 206);
		assert.equal(head.body, null);
	});
	test("a missing asset passes through untouched", async () => {
		const r = await serveRange(req("bytes=0-9"), new Response("nf", { status: 404 }));
		assert.equal(r.status, 404);
	});
});

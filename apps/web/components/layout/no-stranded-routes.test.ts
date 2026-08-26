/**
 * NO STRANDED ROUTES — the R12 rule, as a control instead of an audit.
 *
 * Founder ruling R12: "A surface that exists but has no navigation path to it is
 * stranded — /traces/compare is already in that state today and it is exactly the
 * failure we are guarding against."
 *
 * The R12 before-inventory found it by hand. A finding found by hand recurs; this asserts
 * the property on every run. It builds the inbound-link graph the same way the inventory
 * did — every `<Link href>`, `router.push`, `redirect`, plain anchor and nav-config entry —
 * and fails if a route gains zero inbound edges.
 *
 * STRANDED IS ALLOWED, BUT ONLY ON PURPOSE. `DELIBERATE` below is the whole point: a
 * route may be unreachable if someone wrote down WHY. An empty allowlist would be
 * unmaintainable and would get deleted; an allowlist with no reasons is a list of
 * excuses. Adding a route here is a decision a reviewer can see in the diff.
 *
 * HONEST LIMIT, stated because it changes what a pass means: this is a STATIC read of
 * the source. It proves a link EXISTS in the code, not that the link renders for a given
 * plan, role or entitlement — an entitlement-gated link that never renders would still
 * pass here. The rendered half is `shell-nav-render.test.tsx`, which asserts real markup.
 * Together they cover reachability; neither does alone.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { describe, expect, it } from "vitest";

const APP = join(__dirname, "..", "..", "app");
const SCAN_DIRS = [APP, join(__dirname, "..", "..", "components")];

/** Routes with no inbound link, each with the reason it is allowed to have none. */
const DELIBERATE: Record<string, string> = {
	"/datasets": "V1.1 ComingSoon stub — nav-config.tsx keeps it out until built",
	"/playground": "V1.1 ComingSoon stub — same",
	"/legal/[doc]": "linked from marketing/external, not from app chrome",
	"/": "root redirect — the entry point itself, nothing links to it internally",
};

function walk(dir: string, out: string[] = []): string[] {
	for (const e of readdirSync(dir)) {
		if (e === "node_modules" || e.startsWith(".")) continue;
		const full = join(dir, e);
		if (statSync(full).isDirectory()) walk(full, out);
		else out.push(full);
	}
	return out;
}

/** `app/traces/[traceId]/page.tsx` → `/traces/[traceId]`; route groups `(x)` drop out. */
function routeOf(file: string): string {
	const rel = relative(APP, file).split(sep).slice(0, -1);
	const segs = rel.filter((s) => !(s.startsWith("(") && s.endsWith(")")));
	return `/${segs.join("/")}`;
}

const files = walk(APP);
const pages = files.filter((f) => f.endsWith(`${sep}page.tsx`));
const routes = pages.map(routeOf);

/**
 * Extract ACTUAL navigation targets, per file, and remember which file each came from.
 *
 * The first version of this matched any occurrence of the path anywhere in the tree, and
 * reported `/datasets`, `/experiments` and `/playground` as linked — they are not. It was
 * matching a COMMENT in nav-config.tsx that names them as deliberately excluded, and the
 * routes' own page files. A probe that cannot tell a link from a mention of a link is not
 * a control (`docs/reference/TRAPS.md` §19: match the CONSTRUCTION, not the word), and it
 * fails in the flattering direction — it reports everything as reachable.
 */
/**
 * COMMENTS ARE STRIPPED FIRST, and that is the discriminator.
 *
 * v1 matched any occurrence of the path anywhere and reported `/datasets`,
 * `/experiments` and `/playground` as linked. They are not: it was matching a COMMENT in
 * nav-config.tsx that names them as deliberately excluded. v2 matched only `href=` /
 * `router.push(` and missed BOTH real cases — `/guardrails/verdicts` is built by a
 * function that RETURNS a template literal, and `/settings/account` lives in a config
 * array as `href:`. One probe was too loose, the next too tight, and each failed in a
 * different direction.
 *
 * What actually separates a link from a mention is not the syntax around it — it is
 * whether it is CODE at all. So: strip comments, then take every path literal, then
 * discard the route's own directory (a back-link is not an inbound edge — precisely how
 * /traces/compare looked reachable).
 */
function stripComments(src: string): string {
	// Replace in place rather than deleting lines: a line carrying `*/` also carries
	// code, and dropping whole lines swallows it.
	return src
		.replace(/\/\*[\s\S]*?\*\//g, " ")
		.replace(/(^|[^:"'`])\/\/[^\n]*/g, "$1");
}

/** Any `"/path"` or `` `/path...` `` literal appearing in CODE. */
/**
 * A `${…}` interpolation inside a template literal IS one route segment.
 *
 * WITHOUT THIS THE EXTRACTOR CREDITS THE WRONG ROUTE, and that is not theoretical
 * — it fired the day the first mid-path dynamic route landed.
 * `router.push(`/experiments/${id}`)` navigates to `/experiments/[experimentId]`,
 * but PATH_RE stops at the `$` and records `/experiments`. So the LIST page was
 * reported as linked (it is not — it is deliberately out of the nav) while the
 * DETAIL page it actually navigates to got no credit at all. One truncation,
 * wrong in both directions at once.
 *
 * Collapsing the interpolation to a placeholder segment — and collapsing a route
 * pattern's `[param]` to the same placeholder — makes the two comparable, so
 * `/experiments/_D_/compare` matches `/experiments/[experimentId]/compare`
 * exactly. It is a TIGHTENING: every edge it adds names a real route pattern, and
 * every edge it removes was pointing at the wrong one.
 *
 * Non-greedy to the FIRST `}` — the real shapes are `${id}` and
 * `${encodeURIComponent(id)}`, neither with a nested brace. A nested one would
 * leave the tail unmatched, which fails toward "stranded" (loud) rather than
 * toward "reachable" (silent).
 */
const DYN = "_D_";
function collapseInterpolations(src: string): string {
	return src.replace(/\$\{[\s\S]*?\}/g, DYN);
}

/** A route pattern in the same vocabulary: `/x/[id]/y` -> `/x/_D_/y`. */
function collapseParams(route: string): string {
	return route.replace(/\[[^\]]+\]/g, DYN);
}

const PATH_RE = /["`](\/[a-z0-9][a-z0-9/_-]*)/gi;

const perFile = SCAN_DIRS.flatMap((d) => walk(d))
	.filter((f) => /\.(tsx?|ts)$/.test(f) && !/\.test\.tsx?$/.test(f))
	.map((f) => ({
		file: f,
		text: collapseInterpolations(stripComments(readFileSync(f, "utf8"))),
	}));

/** target path -> the files that reference it */
const inbound = new Map<string, Set<string>>();
for (const { file, text } of perFile) {
	for (const m of text.matchAll(PATH_RE)) {
		const raw = (m[1] ?? "").replace(/\/$/, "");
		if (!inbound.has(raw)) inbound.set(raw, new Set());
		inbound.get(raw)?.add(file);
	}
}

function hasInbound(route: string): boolean {
	if (route === "/") return true;
	// Compared in the COLLAPSED vocabulary, so an interpolated href matches the
	// route pattern it actually navigates to.
	const pattern = collapseParams(route);
	const stem = pattern.replace(new RegExp(`/${DYN}$`), "");
	const ownDir = join(APP, ...route.split("/").filter(Boolean));
	for (const [target, files] of inbound) {
		if (target !== pattern && target !== stem && !target.startsWith(`${stem}/`))
			continue;
		for (const f of files) if (!f.startsWith(ownDir)) return true;
	}
	return false;
}

describe("no stranded routes", () => {
	it("enumerated the route table at all (a probe that finds nothing proves nothing)", () => {
		expect(routes.length).toBeGreaterThan(20);
		expect(routes).toContain("/traces/compare");
	});

	it("every route has an inbound link, or a written reason it does not", () => {
		const stranded = routes.filter((r) => !hasInbound(r) && !(r in DELIBERATE));
		expect(
			stranded,
			`Stranded route(s) — they render but nothing navigates to them. Add a link, or add an entry to DELIBERATE with the reason:\n  ${stranded.join("\n  ")}`,
		).toEqual([]);
	});

	it("/traces/compare is reachable — the founder's named example", () => {
		// It was stranded until 2026-08-15: a working span diff with zero inbound links
		// and an empty state telling the reader to use a control that did not exist.
		expect(hasInbound("/traces/compare")).toBe(true);
		// ...and specifically from the trace-detail Compare control, not just anywhere.
		expect(inbound.get("/traces/compare")).toBeTruthy();
	});

	it("keeps the DELIBERATE list honest — no entry for a route that IS linked", () => {
		// An allowlist that outlives its reason is how a real regression hides.
		const stale = Object.keys(DELIBERATE).filter(
			(r) => r !== "/" && hasInbound(r),
		);
		expect(
			stale,
			`These are listed as deliberately unreachable but now HAVE inbound links — drop them from DELIBERATE:\n  ${stale.join("\n  ")}`,
		).toEqual([]);
	});
});

/**
 * A next/link `<Link>` is PREFETCHED when it renders: Next fetches its target in
 * the background. When the target is a route handler (app/**\/route.ts) that
 * fetch RUNS the handler's GET — `/sign-out` signed the user out, from
 * /organization-deleted, without a click (found by the B-579 CSP probe as a
 * refused `connect-src` to api.workos.com). Route handlers are reached with a
 * plain `<a>` (or `window.location`), never `<Link>` or `router.push` — a client
 * navigation fetches the handler with `?_rsc` first, the same way.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(__dirname, "..");

function walk(dir: string, out: string[] = []): string[] {
	for (const name of readdirSync(dir)) {
		if (name === "node_modules" || name.startsWith(".")) continue;
		const p = join(dir, name);
		if (statSync(p).isDirectory()) walk(p, out);
		else out.push(p);
	}
	return out;
}

// app/sign-out/route.ts -> ^/sign-out$ ; [id] segments match one path segment.
function handlerPatterns(): RegExp[] {
	return walk(join(ROOT, "app"))
		.filter((f) => /[\\/]route\.(ts|tsx|js)$/.test(f))
		.map((f) => {
			const segs = relative(join(ROOT, "app"), f)
				.split(sep)
				.slice(0, -1)
				.filter((s) => !/^\(.*\)$/.test(s)); // route groups add no segment
			const body = segs
				.map((s) =>
					/^\[.*\]$/.test(s)
						? "[^/?#]+"
						: s.replace(/[.*+?^${}()|\\]/g, "\\$&"),
				)
				.join("/");
			return new RegExp(`^/${body}/?(?:[?#].*)?$`);
		});
}

function linkHrefs(): { file: string; href: string }[] {
	const found: { file: string; href: string }[] = [];
	for (const dir of ["app", "components"]) {
		for (const f of walk(join(ROOT, dir))) {
			if (!/\.tsx$/.test(f) || /\.test\.tsx$/.test(f)) continue;
			const src = readFileSync(f, "utf8");
			for (const m of src.matchAll(
				/<Link\b[^>]*?\bhref=\{?["'`]([^"'`]+)["'`]/gs,
			)) {
				found.push({ file: relative(ROOT, f), href: m[1] ?? "" });
			}
			for (const m of src.matchAll(
				/\brouter\.(?:push|replace|prefetch)\(\s*["'`]([^"'`]+)["'`]/g,
			)) {
				found.push({ file: relative(ROOT, f), href: m[1] ?? "" });
			}
		}
	}
	return found;
}

describe("no <Link> or router navigation targets a route handler", () => {
	const patterns = handlerPatterns();

	it("finds the route handlers it guards (the scan is not empty)", () => {
		expect(patterns.some((p) => p.test("/sign-out"))).toBe(true);
		expect(linkHrefs().length).toBeGreaterThan(0);
	});

	it("link_guard_still_blocks_route_handlers", () => {
		const bad = linkHrefs().filter(({ href }) =>
			patterns.some((p) => p.test(href)),
		);
		expect(
			bad,
			"use <a> or window.location for route handlers — <Link>/router fetch runs their GET",
		).toEqual([]);
	});
});

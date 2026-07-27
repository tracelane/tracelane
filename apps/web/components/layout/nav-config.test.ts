/**
 *
 * Guards both directions:
 *   - every previously-orphaned page (/sessions, /settings/{providers,team,
 *     workspace}) is now linked in the sidebar (no orphan), and
 *   - every sidebar href maps to a real `app/<href>/page.tsx` (no dead link).
 *
 * Runs in the node env — it reads the route files off disk, so it needs no DOM
 * or Next runtime (the nav data is isolated from `Sidebar`'s `"use client"`).
 */

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { sections } from "./nav-config";

const hrefs = sections.flatMap((s) => s.items.map((i) => i.href));

/** Resolve `app/<href>/page.tsx` relative to this test (apps/web/components/layout). */
function pageFileFor(href: string): string {
	return fileURLToPath(new URL(`../../app${href}/page.tsx`, import.meta.url));
}

describe("sidebar nav-config", () => {
	it("links the previously-orphaned pages", () => {
		for (const href of [
			"/sessions",
			"/settings/providers",
			"/settings/team",
			"/settings/workspace",
		]) {
			expect(hrefs).toContain(href);
		}
	});

	it("every nav href maps to a real route — no dead links", () => {
		const dead = hrefs.filter((href) => !existsSync(pageFileFor(href)));
		expect(dead).toEqual([]);
	});

	it("has no duplicate hrefs", () => {
		expect(new Set(hrefs).size).toBe(hrefs.length);
	});
});

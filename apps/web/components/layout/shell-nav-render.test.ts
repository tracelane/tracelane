/**
 * R12 AFTER-PROOF — the hard gate on the sidebar migration.
 *
 * Founder ruling R12: after the shell phase, every destination in the BEFORE-inventory
 * (`docs/internal/R12_BEFORE_INVENTORY.md`) must be proven still reachable and still
 * rendering, or deliberately struck with a reason. **Nothing may be left stranded.**
 * A previous navigation migration dropped 8 metrics/columns; this is the control that
 * exists so this one cannot.
 *
 * WHY THIS RENDERS INSTEAD OF READING THE CONFIG. `docs/reference/TRAPS.md` §34 was
 * earned in this repo by exactly the mistake this file could have made: asserting a
 * pure helper (`NAV_ITEMS`) and calling the component covered. A test over `NAV_ITEMS`
 * proves the ARRAY is right and says nothing about whether the sidebar renders it,
 * renders it as links, or renders it at all. So every assertion below runs against
 * `renderToStaticMarkup` of the real `Sidebar` — the markup a customer receives.
 *
 * Mutation-proven, as §34 requires: deleting the `{nav}` expression from Sidebar.tsx,
 * or dropping a group from nav-config, turns these red.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ pathname: "/dashboard" }));
vi.mock("next/navigation", () => ({ usePathname: () => h.pathname }));
// next/link renders a plain anchor in this environment.
vi.mock("next/link", () => ({
	default: ({ href, children, ...rest }: Record<string, unknown>) =>
		createElement("a", { href, ...rest }, children as never),
}));

import { Sidebar } from "./Sidebar";
import { sections } from "./nav-config";
import {
	ALL_CHROME_ROUTES,
	NAV_ITEMS,
	SETTINGS_HREF,
	SUPPORT_HREF,
} from "./nav-model";

function render(collapsed = false): string {
	return renderToStaticMarkup(
		createElement(Sidebar, { defaultCollapsed: collapsed }),
	);
}

beforeEach(() => {
	h.pathname = "/dashboard";
});

describe("R12 after-proof — the sidebar strands nothing", () => {
	it("renders EVERY primary destination as a real link", () => {
		const html = render();
		expect(NAV_ITEMS.length).toBe(9); // ADR-074 §6: nine items, no scroll
		for (const { href } of NAV_ITEMS) {
			expect(html, `sidebar dropped ${href}`).toContain(`href="${href}"`);
		}
	});

	it("renders each primary item's label as ADR-074 §6 names it", () => {
		const html = render();
		for (const { href, label } of NAV_ITEMS) {
			expect(html, `${href} lost its label "${label}"`).toContain(label);
		}
		// The §6 short forms specifically — a silent revert to the long labels
		// would still pass a bare href check.
		expect(html).toContain("Signatures");
		expect(html).toContain("SLO");
	});

	it("renders all three ADR-074 groups as small-caps section labels", () => {
		const html = render();
		for (const label of ["Observe", "Prove", "Operate"]) {
			expect(html, `group "${label}" missing`).toContain(label);
		}
		// "Prove" exists as its own top-level group on purpose: verification is a
		// first-class part of the product, so it must be reachable from the nav
		// rather than buried under settings.
		const prove = sections.find((s) => s.label === "Prove");
		expect(prove?.items.map((i) => i.href)).toEqual(["/audit", "/signatures"]);
	});

	it("keeps Settings, Support and Sign out reachable from the account area", () => {
		// ADR-074 §6 moves Settings to the footer and Support into the account menu.
		// The old top bar carried both as bar items; if the menu had not been built,
		// Support would simply have vanished. That is the exact class R12 guards.
		const html = render();
		expect(html).toContain(`href="${SETTINGS_HREF}"`);
		expect(html).toContain(`href="${SUPPORT_HREF}"`);
		expect(html).toContain('href="/sign-out"');
	});

	it("strands nothing when collapsed to the icon rail", () => {
		// The rail is the mitigation for the 240px the sidebar takes from the
		// waterfall (§6). If collapsing dropped links, it would trade one problem
		// for a worse one.
		const html = render(true);
		for (const { href } of NAV_ITEMS) {
			expect(html, `collapsed rail dropped ${href}`).toContain(
				`href="${href}"`,
			);
		}
		expect(html).toContain(`href="${SETTINGS_HREF}"`);
	});

	it("marks exactly the active route, and by aria-current not colour alone", () => {
		h.pathname = "/audit";
		const html = render();
		expect(html).toContain('aria-current="page"');
		expect(html.match(/aria-current="page"/g)?.length).toBe(1);
	});

	it("sweeps /settings/account — reachable but previously outside the dead-button walk", () => {
		// R12 finding: /settings/account renders and is linked from SettingsNav, but
		// was absent from nav-config, so ALL_CHROME_ROUTES never carried it and the
		// sweep never walked it. A live surface nothing checked.
		expect(ALL_CHROME_ROUTES).toContain("/settings/account");
		expect(ALL_CHROME_ROUTES).toContain(SUPPORT_HREF);
	});

	it("carries every nav-config href into the chrome sweep", () => {
		for (const s of sections) {
			for (const i of s.items) {
				expect(ALL_CHROME_ROUTES, `${i.href} not swept`).toContain(i.href);
			}
		}
	});
});

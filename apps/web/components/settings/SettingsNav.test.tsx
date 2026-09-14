/**
 * `SET-36` §7 proof 3 — the rendered markup, not the array (TRAPS §34).
 *
 * A test over `SETTINGS_GROUPS` proves the config is right and says nothing about
 * whether the component renders it, renders it twice (rail + select), or marks the
 * active page. So this renders the real `SettingsNav` and reads the HTML a
 * customer receives.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ pathname: "/settings/billing" }));
vi.mock("next/navigation", () => ({
	usePathname: () => h.pathname,
	useRouter: () => ({ push: () => undefined }),
}));
vi.mock("next/link", () => ({
	default: ({ href, children, ...rest }: Record<string, unknown>) =>
		createElement("a", { href, ...rest }, children as never),
}));

import { SettingsNav } from "./SettingsNav";
import { SETTINGS_GROUPS, SETTINGS_ITEMS } from "./settings-nav-config";

function render(): string {
	return renderToStaticMarkup(createElement(SettingsNav));
}

beforeEach(() => {
	h.pathname = "/settings/billing";
});

describe("SET-36 — SettingsNav renders the one list twice, marks one page", () => {
	it("renders every settings page as a rail link AND a select option", () => {
		const html = render();
		for (const { href, label } of SETTINGS_ITEMS) {
			expect(html, `rail link ${href}`).toContain(`href="${href}"`);
			expect(html, `option ${href}`).toContain(`<option value="${href}"`);
			expect(html, `label ${label}`).toContain(label);
		}
		expect(html.match(/<option /g)?.length).toBe(SETTINGS_ITEMS.length);
	});

	it("renders the four group labels as rail headings and as optgroups", () => {
		const html = render();
		for (const { label } of SETTINGS_GROUPS) {
			// React escapes `&` in attributes and text ("Keys &amp; access").
			const escaped = label.replace(/&/g, "&amp;");
			expect(html).toContain(`<optgroup label="${escaped}"`);
			expect(html).toContain(`>${escaped}</p>`);
		}
		expect(html.match(/<optgroup /g)?.length).toBe(SETTINGS_GROUPS.length);
	});

	it("marks exactly the active page, by aria-current, and selects it", () => {
		const html = render();
		expect(html.match(/aria-current="page"/g)?.length).toBe(1);
		expect(html).toContain('href="/settings/billing" aria-current="page"');
		// The controlled select carries the same answer (React renders the
		// `value` of a controlled <select> as `selected` on the matching option).
		expect(html).toMatch(/<option value="\/settings\/billing"[^>]*selected/);
	});

	it("highlights the parent page for a sub-route", () => {
		h.pathname = "/settings/api-keys/new";
		const html = render();
		expect(html).toContain('href="/settings/api-keys" aria-current="page"');
		expect(html.match(/aria-current="page"/g)?.length).toBe(1);
	});

	it("marks nothing outside /settings rather than guessing", () => {
		h.pathname = "/dashboard";
		expect(render()).not.toContain('aria-current="page"');
	});
});

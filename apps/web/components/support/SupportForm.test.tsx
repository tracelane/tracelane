/**
 * SupportForm render proof.
 *
 * `TABS`/`AREAS` used to be hand-written locally in this file with no test
 * asserting the rendered options matched them — a silent drift between the
 * dropdown a customer sees and the allowlist the route accepts would have
 * shipped invisibly. Now both come from `@/lib/support-taxonomy`, and this
 * test renders the real component (via `renderToStaticMarkup`, the same
 * technique `shell-nav-render.test.ts` and `segmented-control-render.test.tsx`
 * use for a client component with no jsdom environment configured) and
 * asserts every kind and every area is actually IN THE MARKUP — not merely
 * that the source array is right.
 */

import { SUPPORT_AREAS, SUPPORT_KINDS } from "@/lib/support-taxonomy";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SupportForm } from "./SupportForm";

function render(): string {
	return renderToStaticMarkup(h(SupportForm));
}

describe("SupportForm — every option actually renders", () => {
	it("renders all four kinds, including the new Feature request", () => {
		const html = render();
		expect(SUPPORT_KINDS.length).toBe(4);
		for (const { label } of SUPPORT_KINDS) {
			expect(html, `kind "${label}" not rendered`).toContain(label);
		}
		expect(html).toContain("Feature request");
	});

	it("renders all fourteen area options, as real <option> elements", () => {
		const html = render();
		expect(SUPPORT_AREAS.length).toBe(14);
		for (const { key, label } of SUPPORT_AREAS) {
			expect(html, `area "${key}" missing its <option>`).toContain(
				`value="${key}"`,
			);
			// React HTML-escapes `&` to `&amp;` in text content, so a label like
			// "Gateway & providers" must be matched in its escaped form.
			const htmlLabel = label.replace(/&/g, "&amp;");
			expect(html, `area "${key}" label "${label}" missing`).toContain(
				htmlLabel,
			);
		}
		expect((html.match(/<option/g) ?? []).length).toBe(14);
	});

	it("keeps the seven original area keys stable", () => {
		const keys = SUPPORT_AREAS.map((a) => a.key);
		for (const original of [
			"gateway",
			"traces",
			"guardrails",
			"audit",
			"billing",
			"account",
			"other",
		]) {
			expect(keys, `original key "${original}" was renamed/removed`).toContain(
				original,
			);
		}
	});

	it("renders the message field and the Send action", () => {
		const html = render();
		expect(html).toContain("Tell us what&#x27;s on your mind");
		expect(html).toContain(">Send<");
	});
});

import { SegmentedControl } from "@tracelanedev/ui";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

/**
 * SegmentedControl rendered-shape tests.
 *
 * WHY THESE EXIST. The primitive replaced nine hand-rolled controls in one pass,
 * and the three things most likely to be lost in that kind of sweep are invisible
 * in a screenshot: the accessible group name, `aria-busy` while a transition is in
 * flight, and the button/link split. Nothing in `apps/web` renders the primitive
 * under test otherwise — the nine call sites are pages and client components that
 * the unit suite does not mount — so without this file the only proof the
 * attributes survive is reading the source.
 *
 * OBSERVED BLOCKING, not assumed: deleting `aria-busy={pending || undefined}` and
 * `aria-current` from the primitive fails tests 2 and 3 (`expected '<div
 * role="group" …' to contain 'aria-busy="true"'`). A green here is therefore a
 * measurement, not a label.
 *
 * The empty-string case in test 1 is deliberate: three call sites (traces status,
 * traces group-by, verdict decision) use `""` as the value of their "All" option,
 * so `""` is a real option value and a real React key, not an edge case.
 */
describe("SegmentedControl — the attributes a visual sweep cannot see", () => {
	it("renders empty-string option values without a React key warning", () => {
		const warn = vi.spyOn(console, "error").mockImplementation(() => {});
		const html = renderToStaticMarkup(
			h(SegmentedControl, {
				label: "Trace status",
				value: "",
				options: [
					{ value: "", label: "All" },
					{ value: "ok", label: "OK" },
					{ value: "error", label: "Error" },
				],
				onChange: () => {},
			}),
		);
		expect(warn).not.toHaveBeenCalled();
		warn.mockRestore();
		expect(html).toContain('role="group"');
		expect(html).toContain('aria-label="Trace status"');
		expect(html).not.toContain("aria-busy");
		expect((html.match(/<button/g) ?? []).length).toBe(3);
		expect(html).toContain('aria-pressed="true"');
	});

	it("pending sets aria-busy and dims", () => {
		const html = renderToStaticMarkup(
			h(SegmentedControl, {
				label: "Time range",
				value: "24h",
				pending: true,
				options: [
					{ value: "24h", label: "24h" },
					{ value: "7d", label: "7d" },
				],
				onChange: () => {},
			}),
		);
		expect(html).toContain('aria-busy="true"');
		expect(html).toContain("opacity-60");
	});

	it("link mode emits anchors with aria-current on the active option only", () => {
		const html = renderToStaticMarkup(
			h(SegmentedControl, {
				label: "Traces per page",
				value: "50",
				options: [
					{ value: "25", label: "25" },
					{ value: "50", label: "50" },
				],
				hrefFor: (v: string) => `/traces?size=${v}`,
			}),
		);
		expect((html.match(/<a /g) ?? []).length).toBe(2);
		expect(html).toContain('href="/traces?size=25"');
		expect((html.match(/aria-current="true"/g) ?? []).length).toBe(1);
	});
});

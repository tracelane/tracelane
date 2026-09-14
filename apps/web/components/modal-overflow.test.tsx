/**
 * A modal panel taller than the viewport must scroll ITSELF, not overflow the
 * centred scrim — where the region above the container's top edge is unreachable
 * (found 2026-09-07: the EVL-29 "New queue" dialog with a 3-field rubric put its
 * own title out of reach on a 900px screen).
 *
 * Asserted on the rendered markup rather than by measuring a layout, because this
 * suite runs in vitest's `node` environment; the property that matters is that the
 * panel carries BOTH a viewport-relative cap and its own overflow.
 */
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Modal } from "./Modal";

function panelClasses(): string {
	const html = renderToStaticMarkup(
		<Modal onClose={() => {}} title="Tall dialog">
			<p>body</p>
		</Modal>,
	);
	const i = html.indexOf("bg-surface");
	expect(i).toBeGreaterThan(-1);
	const open = html.lastIndexOf("<div", i);
	return html.slice(open, html.indexOf(">", open) + 1);
}

describe("Modal panel overflow", () => {
	it("caps the panel to the viewport so its top can never be clipped", () => {
		expect(panelClasses()).toContain("max-h-[calc(100dvh-2rem)]");
	});

	it("gives the panel its own scroll, so the cap is reachable content", () => {
		expect(panelClasses()).toContain("overflow-y-auto");
	});
});

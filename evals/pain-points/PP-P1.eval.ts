import { describe, it } from "vitest";
import { expect } from "../src/harness.js";

/**
 * PP-P1 — WebGL trace viewer: 60fps at 100K spans
 *
 * Competitor behavior: Langfuse renders traces as DOM elements — SVG or
 * HTML divs. At 1000+ spans the page freezes. Portkey has no trace
 * visualization. Helicone's trace view is a flat log, not a waterfall.
 *
 * Pain: Production agents in multi-agent orchestration can produce 10K–100K
 * spans per run. DOM-based renderers collapse above ~500 elements. Debugging
 * a slow agent with 50K spans is unusable on these platforms.
 *
 * Status (Phase 1b / ADR-046): the deck.gl WebGL waterfall was SUPERSEDED by
 * the DOM "transcript-with-a-spine" viewer, and deck.gl was removed. The
 * 60fps-at-100K-spans GPU claim is therefore NOT a V1 capability — large-trace
 * virtualization is deferred (burndown 3.22/3.23 ABSENT). This eval no longer
 * asserts the dropped WebGL path: it pins that deck.gl stays out and leaves the
 * 100K-span performance assertion skipped with an honest reason (no false pass).
 *
 */
describe("PP-P1: large-trace viewer (transcript-spine; WebGL path superseded)", () => {
	it("deck.gl stays removed — the transcript-spine is the V1 trace viewer", async () => {
		const pkg = await import("../../apps/web/package.json", {
			assert: { type: "json" },
		});
		// deck.gl was dropped with the WebGL waterfall (Phase 1b). The V1 viewer is
		// the DOM transcript-spine; GPU 100K-span rendering is deferred, not shipped.
		expect(Object.keys(pkg.default.dependencies)).not.toContain("deck.gl");
	});

	it("trace detail route exists for rendering", async () => {
		const fs = await import("node:fs");
		const path = await import("node:path");
		const routePath = path.resolve(
			__dirname,
			"../../apps/web/app/traces/[traceId]/page.tsx",
		);
		expect(fs.existsSync(routePath)).toBe(true);
	});

	it.skip("achieves 60fps at 100K spans (deferred — no V1 virtualized renderer)", async () => {
		// Deferred, not a V1 claim: the transcript-spine is DOM-based; 100K-span
		// GPU rendering + virtualization are ABSENT (burndown 3.22/3.23). Do not
		// un-skip / mark green without a real virtualized renderer + measured fps.
	});
});

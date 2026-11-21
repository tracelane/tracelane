// Answer-first Failure Signatures summary (founder 2026-11-19; #386 review semantics).
import { describe, expect, it } from "vitest";
import { summarizeSignatures } from "./summary";

describe("summarizeSignatures", () => {
	it("zero patterns answers the question plainly", () => {
		const s = summarizeSignatures(0, 0, 0, "Last 30 days");
		expect(s.tone).toBe("ok");
		expect(s.headline).toBe("No known failure patterns in the last 30 days");
	});
	it("headline counts DISTINCT patterns; occurrences are named separately", () => {
		const s = summarizeSignatures(1, 500, 12, "Last 7 days");
		expect(s.headline).toBe(
			"1 known failure pattern matched in the last 7 days",
		);
		expect(s.detail).toMatch(
			/^500 occurrences in total\. 12 distinct traces affected\./,
		);
	});
	it("plural patterns and large counts format with separators", () => {
		const s = summarizeSignatures(4, 12345, 9, "Last 30 days");
		expect(s.headline).toBe(
			"4 known failure patterns matched in the last 30 days",
		);
		expect(s.detail).toMatch(/12,345 occurrences/);
	});
	it("singular occurrence and trace", () => {
		expect(summarizeSignatures(1, 1, 1, "Last 24 hours").detail).toMatch(
			/^1 occurrence in total\. 1 distinct trace affected\./,
		);
	});
	it("matches with zero affected traces states 0, it is a reported number", () => {
		expect(summarizeSignatures(2, 3, 0, "Last 1 hour").detail).toMatch(
			/0 distinct traces affected/,
		);
	});
	it("an unreported trace count is said, never shown as zero", () => {
		const d = summarizeSignatures(3, 3, null, "Last 1 hour").detail;
		expect(d).toMatch(/not reported by this gateway/);
		expect(d).not.toMatch(/0 distinct/);
	});
	it("no internal taxonomy ids, versions or jargon in any visible text", () => {
		for (const s of [
			summarizeSignatures(0, 0, 0, "Last 30 days"),
			summarizeSignatures(5, 9, 2, "Last 30 days"),
			summarizeSignatures(2, 2, null, "x"),
		])
			expect(`${s.headline} ${s.detail}`).not.toMatch(
				/AFT-\d|V\d\.\d|canonical|per-tenant|taxonomy/i,
			);
	});
	it("never claims prevention (observe-first)", () => {
		for (const m of [0, 1, 99])
			expect(summarizeSignatures(m, m, 1, "Last 30 days").detail).not.toMatch(
				/prevent|block/i,
			);
	});
});

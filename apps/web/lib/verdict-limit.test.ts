/**
 * Tests for lib/verdict-limit — the guardrail verdict-list `?limit=` clamp
 * (B-335b). Pure function, no mocks.
 */

import { describe, expect, it } from "vitest";
import {
	DEFAULT_VERDICT_LIMIT,
	MAX_VERDICT_LIMIT,
	clampVerdictLimit,
} from "./verdict-limit";

describe("clampVerdictLimit", () => {
	it("defaults to DEFAULT_VERDICT_LIMIT when absent", () => {
		expect(clampVerdictLimit(undefined)).toBe(DEFAULT_VERDICT_LIMIT);
	});

	it("passes through a valid value inside the range", () => {
		expect(clampVerdictLimit("250")).toBe(250);
	});

	it("clamps down to MAX_VERDICT_LIMIT — never exceeds the gateway's cap", () => {
		expect(clampVerdictLimit("500")).toBe(MAX_VERDICT_LIMIT);
		expect(clampVerdictLimit("501")).toBe(MAX_VERDICT_LIMIT);
		expect(clampVerdictLimit("999999")).toBe(MAX_VERDICT_LIMIT);
	});

	it("falls back to DEFAULT_VERDICT_LIMIT on zero, negative or non-numeric input", () => {
		expect(clampVerdictLimit("0")).toBe(DEFAULT_VERDICT_LIMIT);
		expect(clampVerdictLimit("-5")).toBe(DEFAULT_VERDICT_LIMIT);
		expect(clampVerdictLimit("not-a-number")).toBe(DEFAULT_VERDICT_LIMIT);
		expect(clampVerdictLimit("")).toBe(DEFAULT_VERDICT_LIMIT);
	});

	it("truncates a decimal to its integer part rather than rejecting it", () => {
		expect(clampVerdictLimit("150.9")).toBe(150);
	});

	it("MAX_VERDICT_LIMIT is exactly the gateway's cap (trace_reads.rs)", () => {
		// Kept as a literal assertion, not just re-exported, so a future rename
		// on either side of the seam breaks this test rather than passing silently.
		expect(MAX_VERDICT_LIMIT).toBe(500);
	});
});

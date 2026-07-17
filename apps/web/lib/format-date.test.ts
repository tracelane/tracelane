import { describe, expect, it } from "vitest";
import { absoluteDate } from "./format-date";

describe("absoluteDate", () => {
	it("renders RFC3339 UTC as 'MMM D, YYYY'", () => {
		expect(absoluteDate("2026-07-11T12:07:23Z")).toBe("Jul 11, 2026");
		expect(absoluteDate("2026-07-07T00:20:54Z")).toBe("Jul 7, 2026");
		expect(absoluteDate("2026-07-03T07:33:40Z")).toBe("Jul 3, 2026");
	});

	// The whole point of the fix (RCA-signatures-first-last-seen-dates): the value
	// is the UTC calendar date, deterministic and clock-free — never a relative
	// "N days ago" that undercounts calendar days or contradicts the paired date.
	it("uses the UTC date, not local-time-shifted (hydration-safe, deterministic)", () => {
		expect(absoluteDate("2026-01-01T00:00:00Z")).toBe("Jan 1, 2026");
		expect(absoluteDate("2025-12-31T23:59:59Z")).toBe("Dec 31, 2025");
	});

	it("returns an em-dash for empty / unparseable input, never 'Invalid Date'", () => {
		expect(absoluteDate("")).toBe("—");
		expect(absoluteDate("not-a-date")).toBe("—");
	});
});

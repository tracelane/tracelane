/**
 * The process is pinned to Asia/Kolkata (+5:30) so the naive-timestamp
 * regression tests actually reproduce the founder's environment: under the old
 * un-anchored `new Date(naiveString)` these FAIL (values shift −5:30); under the
 * `parseUtcMs` fix they pass on every zone. Must run before any Date use — hence
 * top of file, before imports (see the internal naive-timestamp local-parse fix).
 */
process.env.TZ = "Asia/Kolkata";

import { describe, expect, it } from "vitest";
import {
	absoluteDate,
	formatDateTimeUtc,
	formatStartedUtc,
	parseUtcMs,
} from "./format-date";

describe("absoluteDate", () => {
	it("renders RFC3339 UTC as 'MMM D, YYYY'", () => {
		expect(absoluteDate("2026-07-11T12:07:23Z")).toBe("Jul 11, 2026");
		expect(absoluteDate("2026-07-07T00:20:54Z")).toBe("Jul 7, 2026");
		expect(absoluteDate("2026-07-03T07:33:40Z")).toBe("Jul 3, 2026");
	});

	// The whole point of the fix (signatures first/last-seen dates): the value
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

// The exact naive shape the gateway returns (verified on-node 2026-07-21:
// `curl /v1/traces` → '2026-07-21 08:45:53.982997'). The founder in IST saw this
// render as "03:15" — off by the +5:30 offset — on the Traces list.
const NAIVE = "2026-07-21 08:45:53.982997";
const WITH_Z = "2026-07-21T08:45:53.982997Z";
const EXPECTED_MS = Date.UTC(2026, 6, 21, 8, 45, 53, 982); // TZ-independent

describe("parseUtcMs — anchors zone-less gateway timestamps to UTC", () => {
	it("interprets a naive gateway string as UTC, not local (the bug)", () => {
		expect(parseUtcMs(NAIVE)).toBe(EXPECTED_MS);
	});

	it("is identical for the naive and the explicit-Z form", () => {
		expect(parseUtcMs(NAIVE)).toBe(parseUtcMs(WITH_Z));
	});

	it("passes epoch-ms numbers through untouched", () => {
		expect(parseUtcMs(EXPECTED_MS)).toBe(EXPECTED_MS);
	});

	it("leaves an explicit +offset alone (does not double-anchor)", () => {
		// 08:45:53+05:30 == 03:15:53Z
		expect(parseUtcMs("2026-07-21T08:45:53+05:30")).toBe(
			Date.UTC(2026, 6, 21, 3, 15, 53),
		);
	});

	it("parses a date-only string as UTC midnight", () => {
		expect(parseUtcMs("2026-07-21")).toBe(Date.UTC(2026, 6, 21));
	});

	it("returns NaN for empty / unparseable", () => {
		expect(Number.isNaN(parseUtcMs(""))).toBe(true);
		expect(Number.isNaN(parseUtcMs("not-a-date"))).toBe(true);
	});
});

describe("formatters render UTC regardless of viewer zone", () => {
	it('formatStartedUtc: naive 08:45 UTC → "Jul 21, 08:45" (was "03:15" in IST)', () => {
		expect(formatStartedUtc(NAIVE)).toBe("Jul 21, 08:45");
		expect(formatStartedUtc(NAIVE)).toBe(formatStartedUtc(WITH_Z));
	});

	it("formatDateTimeUtc: naive → labeled UTC form", () => {
		expect(formatDateTimeUtc(NAIVE)).toBe("Jul 21, 2026 · 08:45 UTC");
	});

	it("absoluteDate: naive → UTC calendar day (no local off-by-one)", () => {
		// 00:30 UTC would render as the previous day if parsed as local behind UTC.
		expect(absoluteDate("2026-07-21 00:30:00")).toBe("Jul 21, 2026");
		expect(absoluteDate(NAIVE)).toBe("Jul 21, 2026");
	});
});

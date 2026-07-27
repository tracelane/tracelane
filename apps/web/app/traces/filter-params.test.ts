/**
 * Tests for `nextFilterParams` — the traces filter-bar URL transition. The
 * headline is the founder-caught bug: picking a range preset must CLEAR a
 * lingering custom `since`/`until` window (else the server's
 * `sp.since ?? rangeSince(range)` keeps the old window and the preset shows rows
 * outside the picked range). Negative/edge cases alongside per testing rules.
 */

import { describe, expect, it } from "vitest";
import { nextFilterParams } from "./filter-params";

const parse = (qs: string) => new URLSearchParams(qs);

describe("nextFilterParams", () => {
	it("BUG FIX: picking a range preset clears a stale since/until window", () => {
		// URL still carries a dashboard chart-click window; user clicks "1h".
		const cur = parse(
			"since=2026-07-20T10:00:00Z&until=2026-07-20T11:00:00Z&status=error",
		);
		const out = parse(nextFilterParams(cur, "range", "1h"));
		expect(out.get("range")).toBe("1h");
		expect(out.get("since")).toBeNull(); // ← cleared, so the preset actually applies
		expect(out.get("until")).toBeNull();
		expect(out.get("status")).toBe("error"); // unrelated filters preserved
	});

	it("range=all also clears the custom window", () => {
		const cur = parse("since=2026-07-20T10:00:00Z&until=2026-07-20T11:00:00Z");
		const out = parse(nextFilterParams(cur, "range", "all"));
		expect(out.get("range")).toBe("all");
		expect(out.get("since")).toBeNull();
		expect(out.get("until")).toBeNull();
	});

	it("a NON-range filter change leaves since/until untouched", () => {
		const cur = parse("since=2026-07-20T10:00:00Z&range=7d");
		const out = parse(nextFilterParams(cur, "status", "error"));
		expect(out.get("since")).toBe("2026-07-20T10:00:00Z");
		expect(out.get("range")).toBe("7d");
		expect(out.get("status")).toBe("error");
	});

	it("any filter change resets the pagination cursor", () => {
		const cur = parse("cursor=abc123&range=24h");
		expect(
			parse(nextFilterParams(cur, "status", "ok")).get("cursor"),
		).toBeNull();
	});

	it("empty value deletes the key", () => {
		const cur = parse("status=error&range=1h");
		expect(parse(nextFilterParams(cur, "status", "")).get("status")).toBeNull();
	});
});

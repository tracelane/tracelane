import { describe, expect, it } from "vitest";
import {
	BUCKET_LADDER_MS,
	MAX_BUCKETS,
	MAX_WINDOW_MS,
	bucketFor,
	bucketGrid,
	bucketHref,
	bucketParam,
	formatWindowUtc,
	parseInstant,
	parseTimeRange,
	windowParams,
	withWindow,
} from "./time-range";

const H = 3_600_000;
const M = 60_000;
// 2026-09-02T10:17:23.456Z — deliberately NOT on a bucket boundary, so the edge
// buckets of a rolling window are partial and the tests can see it.
const NOW = Date.parse("2026-09-02T10:17:23.456Z");
const base = { defaultPreset: "24h" as const, nowMs: NOW };

describe("parseTimeRange — the one grammar", () => {
	it("defaults to the page preset when nothing is given", () => {
		const r = parseTimeRange({}, base);
		expect(r.kind).toBe("preset");
		expect(r.preset).toBe("24h");
		expect(r.untilMs).toBe(NOW);
		expect(r.sinceMs).toBe(NOW - 24 * H);
		expect(r.invalid).toBe(false);
		expect(r.label).toBe("last 24 hours");
	});

	it("honours every preset with its exact width", () => {
		for (const [p, hours] of [
			["1h", 1],
			["6h", 6],
			["24h", 24],
			["7d", 168],
			["30d", 720],
		] as const) {
			const r = parseTimeRange({ range: p }, base);
			expect(r.widthMs).toBe(hours * H);
			expect(r.short).toBe(p);
		}
	});

	it("reads an absolute window and keeps it exact", () => {
		const r = parseTimeRange(
			{ since: "2026-09-01T14:00:00Z", until: "2026-09-01T17:00:00Z" },
			base,
		);
		expect(r.kind).toBe("custom");
		expect(r.preset).toBeNull();
		expect(r.widthMs).toBe(3 * H);
		expect(r.label).toBe("2026-09-01 14:00 → 17:00 UTC");
		expect(r.short).toBe("custom");
	});

	it("`since` WINS over a stale `range` beside it", () => {
		const r = parseTimeRange(
			{ range: "7d", since: "2026-09-02T09:00:00Z" },
			base,
		);
		expect(r.kind).toBe("custom");
		expect(r.untilMs).toBe(NOW); // since alone → ends now
	});

	it("clamps a window wider than the cap to the most recent cap and SAYS so", () => {
		const r = parseTimeRange(
			{ since: "2025-09-02T00:00:00Z", until: "2026-09-02T00:00:00Z" },
			base,
		);
		expect(r.clamped).toBe(true);
		expect(r.widthMs).toBe(MAX_WINDOW_MS);
		expect(r.untilMs).toBe(Date.parse("2026-09-02T00:00:00Z"));
		expect(r.sinceMs).toBe(r.untilMs - MAX_WINDOW_MS);
		expect(r.requestedWidthMs).toBe(365 * 24 * H);
	});

	it("a family cap is honoured (sessions: 90 d)", () => {
		const r = parseTimeRange(
			{ since: "2026-01-01T00:00:00Z", until: "2026-09-01T00:00:00Z" },
			{ ...base, maxWidthMs: 90 * 24 * H },
		);
		expect(r.clamped).toBe(true);
		expect(r.widthMs).toBe(90 * 24 * H);
	});

	it("falls back — flagged — on garbage, an inverted pair, or an unknown preset", () => {
		for (const sp of [
			{ since: "yesterday" },
			{ since: "2026-09-02T09:00:00Z", until: "2026-09-02T08:00:00Z" },
			{ range: "90d" },
			{ range: "all" },
		]) {
			const r = parseTimeRange(sp, base);
			expect(r.invalid).toBe(true);
			expect(r.preset).toBe("24h");
		}
	});

	it("never runs into the future", () => {
		const r = parseTimeRange(
			{ since: "2026-09-02T10:00:00Z", until: "2026-09-03T10:00:00Z" },
			base,
		);
		expect(r.untilMs).toBe(NOW);
	});
});

describe("parseInstant", () => {
	it("reads ISO with a zone, a naive UTC string, and epoch ms/secs", () => {
		expect(parseInstant("2026-09-02T10:00:00Z")).toBe(
			Date.parse("2026-09-02T10:00:00Z"),
		);
		expect(parseInstant("2026-09-02 10:00:00")).toBe(
			Date.parse("2026-09-02T10:00:00Z"),
		);
		expect(parseInstant("1788343200000")).toBe(1788343200000);
		expect(parseInstant("1788343200")).toBe(1788343200000);
		expect(parseInstant("nope")).toBeNull();
		expect(parseInstant("")).toBeNull();
	});
});

describe("bucketFor — the ladder from the spec table", () => {
	it("picks the spec's bucket for each preset width", () => {
		expect(bucketFor(1 * H)).toBe(1 * M);
		expect(bucketFor(6 * H)).toBe(5 * M);
		expect(bucketFor(24 * H)).toBe(30 * M);
		expect(bucketFor(72 * H, { floorMs: H })).toBe(1 * H);
		expect(bucketFor(168 * H, { floorMs: H })).toBe(3 * H);
		expect(bucketFor(720 * H, { floorMs: H })).toBe(12 * H);
	});

	it("never exceeds MAX_BUCKETS and never returns a value off the ladder (below the top)", () => {
		for (const w of [M, 7 * M, 90 * M, 5 * H, 26 * H, 100 * H, 720 * H]) {
			const b = bucketFor(w);
			expect(w / b).toBeLessThanOrEqual(MAX_BUCKETS);
			expect(
				BUCKET_LADDER_MS.includes(b as (typeof BUCKET_LADDER_MS)[number]) ||
					b > (BUCKET_LADDER_MS[BUCKET_LADDER_MS.length - 1] ?? 0),
			).toBe(true);
		}
	});

	it("floors at the hourly view for windows wider than a day via parseTimeRange", () => {
		const r = parseTimeRange(
			{ since: "2026-08-31T00:00:00Z", until: "2026-09-02T00:00:00Z" },
			base,
		);
		expect(r.bucketMs).toBe(H);
		const s = parseTimeRange({ range: "6h" }, base);
		expect(s.bucketMs).toBe(5 * M);
	});
});

describe("bucketGrid — epoch-aligned, edges flagged", () => {
	it("an arbitrary 3-day window at 1 h is exactly 72 buckets with no partial edges", () => {
		const r = parseTimeRange(
			{ since: "2026-08-30T00:00:00Z", until: "2026-09-02T00:00:00Z" },
			base,
		);
		const g = bucketGrid(r);
		expect(g).toHaveLength(72);
		expect(g[0]?.t).toBe(r.sinceMs);
		expect(g[71]?.tEnd).toBe(r.untilMs);
		expect(g.some((b) => b.partial)).toBe(false);
	});

	it("moving the bounds off the hour flags exactly the first and last bucket", () => {
		const r = parseTimeRange(
			{ since: "2026-08-30T00:23:00Z", until: "2026-09-02T00:41:00Z" },
			base,
		);
		const g = bucketGrid(r);
		expect(g[0]?.partial).toBe(true);
		expect(g[g.length - 1]?.partial).toBe(true);
		expect(g.slice(1, -1).some((b) => b.partial)).toBe(false);
		// Buckets are ALIGNED: the first starts on the hour before `since`.
		expect(g[0]?.t).toBe(Date.parse("2026-08-30T00:00:00Z"));
	});

	it("a rolling preset has a partial last bucket (now is mid-bucket)", () => {
		const r = parseTimeRange({ range: "24h" }, base);
		const g = bucketGrid(r);
		expect(g[g.length - 1]?.partial).toBe(true);
		expect(g.length).toBeLessThanOrEqual(MAX_BUCKETS);
	});
});

describe("gateway params and hrefs", () => {
	it("windowParams emits RFC3339 since/until and the bucket in the unit the route takes", () => {
		const r = parseTimeRange({ range: "6h" }, base);
		const q = windowParams(r, { bucket: true });
		expect(q.get("since")).toBe(new Date(NOW - 6 * H).toISOString());
		expect(q.get("until")).toBe(new Date(NOW).toISOString());
		expect(q.get("bucket_minutes")).toBe("5");
		expect(q.get("bucket")).toBeNull();
		expect(q.get("hours")).toBeNull();
		const d = parseTimeRange({ range: "7d" }, base);
		expect(windowParams(d, { bucket: true }).get("bucket")).toBe("3");
	});

	it("bucketParam switches unit at one hour", () => {
		expect(bucketParam(30 * M)).toEqual({ name: "bucket_minutes", value: 30 });
		expect(bucketParam(H)).toEqual({ name: "bucket", value: 1 });
	});

	it("withWindow keeps a preset rolling and writes a custom window as the pair", () => {
		const p = parseTimeRange({ range: "7d" }, base);
		expect(withWindow("/traces", p, { status: "error" })).toBe(
			"/traces?status=error&range=7d",
		);
		const c = parseTimeRange(
			{ since: "2026-09-01T14:00:00Z", until: "2026-09-01T17:00:00Z" },
			base,
		);
		const href = withWindow("/traces", c);
		expect(href).toContain("since=2026-09-01T14%3A00%3A00.000Z");
		expect(href).toContain("until=2026-09-01T17%3A00%3A00.000Z");
		expect(href).not.toContain("range=");
	});

	it("bucketHref carries the bucket's own bounds, never the whole range", () => {
		const href = bucketHref(
			"/traces",
			{
				t: Date.parse("2026-09-01T14:25:00Z"),
				tEnd: Date.parse("2026-09-01T14:30:00Z"),
			},
			{ status: "error" },
		);
		expect(href).toBe(
			"/traces?status=error&since=2026-09-01T14%3A25%3A00.000Z&until=2026-09-01T14%3A30%3A00.000Z",
		);
	});

	it("formatWindowUtc drops the date on the end when it is the same UTC day", () => {
		expect(
			formatWindowUtc(
				Date.parse("2026-09-01T14:00:00Z"),
				Date.parse("2026-09-01T17:00:00Z"),
			),
		).toBe("2026-09-01 14:00 → 17:00 UTC");
		expect(
			formatWindowUtc(
				Date.parse("2026-08-30T00:00:00Z"),
				Date.parse("2026-09-02T00:00:00Z"),
			),
		).toBe("2026-08-30 00:00 → 2026-09-02 00:00 UTC");
	});
});

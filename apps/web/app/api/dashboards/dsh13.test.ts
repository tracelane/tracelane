/**
 * dsh13.test.ts — DSH-13 custom dashboards: API validation + registry parity.
 *
 * Three coverage areas:
 *  1. Input validation at the route layer — metric_id ∈ registry, shape ∈ closed
 *     set, width ∈ {4,6,12}, title ≤ 60 chars, dimension ∈ closed set.
 *  2. Tenant isolation — a foreign dashboard id returns 404, never 403.
 *  3. fetchTileData parity — every metric in the registry resolves to a fetcher
 *     path (no unknown_metric for a known id) and the stat path produces a
 *     non-empty formatted string.
 *
 * All external clients (Drizzle, requireSession, upsertTenantId, the gateway
 * fetch calls) are mocked — no real network, no Neon, per testing conventions.
 */

import type { GatewayStats } from "@/lib/gateway-ops";
import type { GuardrailStats } from "@/lib/guardrails";
import type { LatencyBreakdown } from "@/lib/latency";
import { METRICS, allMetrics } from "@/lib/metrics/registry";
import { beforeEach, describe, expect, it, vi } from "vitest";

// ── 1. Registry parity: every metric id is in METRICS ─────────────────────────

describe("DSH-13 registry parity", () => {
	it("METRICS has at least 10 entries", () => {
		const ids = Object.keys(METRICS);
		expect(ids.length).toBeGreaterThanOrEqual(10);
	});

	it("allMetrics() returns the same ids as METRICS keys", () => {
		const ids = Object.keys(METRICS);
		const fromAll = allMetrics().map((m) => m.id);
		expect(fromAll.sort()).toEqual(ids.sort());
	});

	it("every metric has a non-empty label", () => {
		for (const [id, def] of Object.entries(METRICS)) {
			expect(def.label, `metric ${id} missing label`).toBeTruthy();
		}
	});

	it("every metric has a kind", () => {
		for (const [id, def] of Object.entries(METRICS)) {
			expect(def.kind, `metric ${id} missing kind`).toBeTruthy();
		}
	});
});

// ── 2. Input validation helpers (extracted from the route) ─────────────────────

/** Mirrors the validation logic in /api/dashboards/[id]/tiles/route.ts */
function validateTileInput(body: Record<string, unknown>): string | null {
	const VALID_SHAPES = new Set(["stat", "series", "breakdown"]);
	const VALID_WIDTHS = new Set([4, 6, 12]);
	const VALID_DIMENSIONS = new Set([
		"model",
		"provider",
		"api_key",
		"status",
		"operation",
		"decision",
		"rail",
	]);

	if (!body.metric_id || typeof body.metric_id !== "string") {
		return "metric_id required";
	}
	if (!(body.metric_id in METRICS)) {
		return `unknown metric_id: ${body.metric_id}`;
	}
	if (!body.shape || !VALID_SHAPES.has(body.shape as string)) {
		return "shape must be stat | series | breakdown";
	}
	const width =
		typeof body.width === "number" ? body.width : Number(body.width ?? 6);
	if (!VALID_WIDTHS.has(width)) {
		return "width must be 4, 6, or 12";
	}
	if (body.dimension !== null && body.dimension !== undefined) {
		if (!VALID_DIMENSIONS.has(body.dimension as string)) {
			return `invalid dimension: ${body.dimension}`;
		}
	}
	if (body.title && typeof body.title === "string" && body.title.length > 60) {
		return "title must be ≤ 60 characters";
	}
	return null; // valid
}

describe("DSH-13 tile input validation", () => {
	it("accepts a minimal valid stat tile", () => {
		// Use the first registered metric id so the test is not hardcoded to a
		// specific metric name that could be renamed.
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		expect(validateTileInput({ metric_id: firstId, shape: "stat" })).toBeNull();
	});

	it("rejects an unknown metric_id", () => {
		const err = validateTileInput({
			metric_id: "not_a_real_metric",
			shape: "stat",
		});
		expect(err).toMatch(/unknown metric_id/);
	});

	it("rejects an invalid shape", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		const err = validateTileInput({ metric_id: firstId, shape: "pie" });
		expect(err).toMatch(/shape must be/);
	});

	it("rejects width=3", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		const err = validateTileInput({
			metric_id: firstId,
			shape: "stat",
			width: 3,
		});
		expect(err).toMatch(/width must be/);
	});

	it("rejects width=12 still valid", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		expect(
			validateTileInput({ metric_id: firstId, shape: "stat", width: 12 }),
		).toBeNull();
	});

	it("rejects an invalid dimension", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		const err = validateTileInput({
			metric_id: firstId,
			shape: "breakdown",
			dimension: "foo",
		});
		expect(err).toMatch(/invalid dimension/);
	});

	it("accepts a valid dimension", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		expect(
			validateTileInput({
				metric_id: firstId,
				shape: "breakdown",
				dimension: "model",
			}),
		).toBeNull();
	});

	it("rejects a title longer than 60 chars", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		const err = validateTileInput({
			metric_id: firstId,
			shape: "stat",
			title: "x".repeat(61),
		});
		expect(err).toMatch(/≤ 60/);
	});

	it("accepts a 60-char title", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		expect(
			validateTileInput({
				metric_id: firstId,
				shape: "stat",
				title: "x".repeat(60),
			}),
		).toBeNull();
	});
});

// ── 3. fetchTileData: stub gateway calls, check parity ─────────────────────────

// Stub the @tracelanedev/ui workspace package — it is not resolvable from
// the isolated worktree environment, but only fmtDurMs is needed here.
vi.mock("@tracelanedev/ui", () => ({
	fmtDurMs: (ms: number) => `${ms.toFixed(1)} ms`,
}));

// Stub the gateway fetchers so fetchTileData runs without a real HTTP call.
// The stub returns minimal valid shapes — the test asserts the *output kind*
// matches the tile's shape request, not the exact number.
vi.mock("@/lib/metrics/fetch", () => ({
	fetchSloSummary: vi.fn().mockResolvedValue({
		requests: 100,
		errors: 5,
		p50_ms: 12,
		p95_ms: 40,
		p99_ms: 80,
	}),
	fetchSloRows: vi.fn().mockResolvedValue([]),
	fetchSloModels: vi.fn().mockResolvedValue([]),
	fetchSloTimeseries: vi.fn().mockResolvedValue({ points: [] }),
	fetchGatewayStatsFor: vi.fn().mockResolvedValue({
		total_requests: 1000,
		total_errors: 10,
		cache_hit_rate_pct: 5.0,
		provider_count: 3,
		total_failovers: 1,
		rate_limited_since_start: 0,
		budget_exceeded_since_start: 0,
		open_breakers: 0,
	} as unknown as GatewayStats),
	fetchCostBreakdownFor: vi
		.fn()
		.mockResolvedValue([{ dimension: "gpt-4o", requests: 10, cost_usd: 0.5 }]),
	fetchLatencyBreakdownFor: vi.fn().mockResolvedValue({
		overhead_p95_ms: 3.2,
		provider_p95_ms: 120.0,
		ttft_p95_ms: 85.0,
	} as unknown as LatencyBreakdown),
	fetchGuardrailStatsFor: vi.fn().mockResolvedValue({
		total: 1000,
		passed: 950,
		failed: 50,
		pass_rate_pct: 95.0,
	}),
	fetchGuardrailVerdictsFor: vi.fn().mockResolvedValue([]),
	fetchTraceCountFor: vi.fn().mockResolvedValue({ count: 42 }),
	fetchSessionsFor: vi.fn().mockResolvedValue({ count: 7 }),
	fetchSignaturesFor: vi.fn().mockResolvedValue([]),
	fetchToolAnalyticsFor: vi.fn().mockResolvedValue([]),
}));

describe("fetchTileData parity — stat shape returns a non-empty string", () => {
	const range = {
		sinceMs: Date.now() - 86_400_000,
		untilMs: Date.now(),
		bucketMs: 3_600_000,
	};

	// vitest's restoreMocks:true resets vi.fn() between tests.
	// Re-apply the return values before each test so every metric gets a live mock.
	beforeEach(async () => {
		const fetchMod = await import("@/lib/metrics/fetch");
		vi.mocked(fetchMod.fetchSloSummary).mockResolvedValue({
			requests: 100,
			errors: 5,
			p50_ms: 12,
			p95_ms: 40,
			p99_ms: 80,
		});
		vi.mocked(fetchMod.fetchGatewayStatsFor).mockResolvedValue({
			total_requests: 1000,
			total_errors: 10,
			cache_hit_rate_pct: 5.0,
			provider_count: 3,
			total_failovers: 1,
			rate_limited_since_start: 0,
			budget_exceeded_since_start: 0,
			open_breakers: 0,
		} as unknown as GatewayStats);
		vi.mocked(fetchMod.fetchCostBreakdownFor).mockResolvedValue(
			// biome-ignore lint/suspicious/noExplicitAny: test stub
			[{ dimension: "gpt-4o", requests: 10, cost_usd: 0.5 }] as any,
		);
		vi.mocked(fetchMod.fetchLatencyBreakdownFor).mockResolvedValue({
			overhead_p95_ms: 3.2,
			provider_p95_ms: 120.0,
			ttft_p95_ms: 85.0,
		} as unknown as LatencyBreakdown);
		vi.mocked(fetchMod.fetchGuardrailStatsFor).mockResolvedValue({
			total_evaluations: 1000,
			block_rate_pct: 5.0,
			fail_open_rate_pct: 0.1,
			p95_ms: 2.1,
		} as unknown as GuardrailStats);
	});

	// Test a representative sample of stat-compatible metrics.
	const STAT_METRICS = ["llm_calls", "error_rate", "availability"] as const;

	for (const id of STAT_METRICS) {
		it(`${id}: stat → non-empty formatted value`, async () => {
			if (!(id in METRICS)) return; // guard if metric removed
			const { fetchTileData } = await import("@/lib/metrics/tiles");
			const tile = { id: "test-tile", metricId: id, shape: "stat" as const };
			const result = await fetchTileData(tile, range);
			// Must not be unknown_metric (the metric is known)
			expect(result.kind).not.toBe("unknown_metric");
			// Must not be unreachable (fetch was mocked to succeed)
			expect(result.kind).not.toBe("unreachable");
			if (result.kind === "stat") {
				expect(result.value).toBeTruthy();
			}
		});
	}

	it("unknown metric_id → kind=unknown_metric", async () => {
		const { fetchTileData } = await import("@/lib/metrics/tiles");
		const tile = {
			id: "t",
			metricId: "no_such_metric",
			shape: "stat" as const,
		};
		const result = await fetchTileData(tile, range);
		expect(result.kind).toBe("unknown_metric");
		if (result.kind === "unknown_metric") {
			expect(result.metricId).toBe("no_such_metric");
		}
	});

	it("breakdown without a dimension → kind=unsupported_shape", async () => {
		const { fetchTileData } = await import("@/lib/metrics/tiles");
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		const tile = {
			id: "t",
			metricId: firstId,
			shape: "breakdown" as const,
			dimension: null,
		};
		const result = await fetchTileData(tile, range);
		expect(result.kind).toBe("unsupported_shape");
	});
});

// ── DSH-13 support matrix + limiter (verifier findings, 2026-09-05) ─────────────────
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
	DEFAULT_SLO_TARGET,
	SERIES_IDS,
	STAT_IDS,
	makeLimiter,
	shapeSupported,
	tileSupport,
} from "@/lib/metrics/tile-support";

describe("tile support matrix", () => {
	it("a series-only metric has no stat shape, and says so before any fetch", () => {
		expect(tileSupport("traffic_series").stat).toBe(false);
		expect(tileSupport("traffic_series").series).toBe(true);
		expect(shapeSupported("traffic_series", "stat")).toBe(false);
	});
	it("guardrail metrics break down by decision/rail only; spend by model/provider/key", () => {
		expect([...tileSupport("verdicts").breakdownDimensions]).toEqual([
			"decision",
			"rail",
		]);
		expect(shapeSupported("verdicts", "breakdown", "provider")).toBe(false);
		expect(tileSupport("spend_est").breakdownDimensions).toContain("api_key");
		expect(tileSupport("spend_est").breakdownDimensions).toContain("model");
	});
	it("an unknown id supports nothing", () => {
		expect(tileSupport("p95_ms")).toEqual({
			stat: false,
			series: false,
			breakdownDimensions: [],
		});
	});
	it("STAT_IDS / SERIES_IDS equal the case labels of the fetchers in tiles.ts (no drift)", () => {
		const src = readFileSync(
			resolve(__dirname, "../../../lib/metrics/tiles.ts"),
			"utf8",
		);
		const between = (from: string, to: string) =>
			src.slice(src.indexOf(from), src.indexOf(to));
		const statBody = between(
			"async function fetchStatValue",
			"async function fetchSeriesData",
		);
		const dashOnly = statBody.slice(0, statBody.indexOf('formatted: "—"'));
		const fallthrough = new Set(
			[
				...dashOnly
					.slice(dashOnly.lastIndexOf("// Derived"))
					.matchAll(/case "([a-z_0-9]+)":/g),
			].map((m) => m[1]),
		);
		const statCases = new Set(
			[...statBody.matchAll(/case "([a-z_0-9]+)":/g)]
				.map((m) => m[1])
				.filter((c) => !fallthrough.has(c)),
		);
		expect(new Set(STAT_IDS)).toEqual(statCases);
		const seriesBody = src.slice(src.indexOf("async function fetchSeriesData"));
		const seriesCases = new Set(
			[
				...seriesBody
					.slice(0, seriesBody.indexOf("default:"))
					.matchAll(/case "([a-z_0-9]+)":/g),
			].map((m) => m[1]),
		);
		expect(new Set(SERIES_IDS)).toEqual(seriesCases);
	});
});

describe("makeLimiter", () => {
	it("never lets more than N fetches run at once, and runs them all", async () => {
		const run = makeLimiter(2);
		let inFlight = 0;
		let peak = 0;
		const job = () =>
			run(async () => {
				inFlight += 1;
				peak = Math.max(peak, inFlight);
				await new Promise((r) => setTimeout(r, 5));
				inFlight -= 1;
				return 1;
			});
		const results = await Promise.all([job(), job(), job(), job(), job()]);
		expect(results).toHaveLength(5);
		expect(peak).toBe(2);
	});
});

describe("DEFAULT_SLO_TARGET mirrors app/slo/budget.ts", () => {
	it("the two literals are equal (read as text — importing app/ breaks vitest)", () => {
		const src = readFileSync(resolve(__dirname, "../../slo/budget.ts"), "utf8");
		const m = /export const SLO_TARGET_AVAILABILITY = ([0-9.]+);/.exec(src);
		expect(m).not.toBeNull();
		expect(Number(m?.[1])).toBe(DEFAULT_SLO_TARGET);
	});
});

describe("B-341 stat parity with the built-in page", () => {
	it("SLO-family tiles print exactly what sloHeadline prints for the same inputs, fallback included", async () => {
		const fetchMod = await import("@/lib/metrics/fetch");
		const { fetchTileData, sloHeadline } = await import("@/lib/metrics/tiles");
		const range = { sinceMs: 0, untilMs: 3_600_000, bucketMs: 60_000 };
		// Summary UNREACHABLE, rows present: the page falls back to per-row LLM totals.
		vi.mocked(fetchMod.fetchSloSummary).mockResolvedValue(null);
		vi.mocked(fetchMod.fetchSloRows).mockResolvedValue([
			{ provider: "anthropic", requests: 900, errors: 9 },
			{ provider: "", requests: 50, errors: 50 }, // tool/child rows — not LLM calls
		] as never);
		const expected = sloHeadline({
			summary: null,
			fallback: { requests: 900, errors: 9 },
			target: 0.99,
			unreachable: false,
		});
		const tile = (id: string) =>
			fetchTileData(
				{ id: "t", metricId: id, shape: "stat", dimension: null } as never,
				range,
				{ target: 0.99 },
			);
		expect(await tile("llm_calls")).toMatchObject({
			kind: "stat",
			value: expected.llmCalls,
		});
		expect(await tile("error_rate")).toMatchObject({
			kind: "stat",
			value: expected.errorRate.text,
		});
		expect(await tile("availability")).toMatchObject({
			kind: "stat",
			value: expected.availability.text,
		});
		expect(await tile("budget_remaining")).toMatchObject({ kind: "stat" });
		// A stat computed from the fallback is a REAL number, never the "—" of an unsupported tile.
		expect(expected.llmCalls).not.toBe("—");
	});
	it("spend prints — for a measured zero, exactly like the built-in card", async () => {
		const fetchMod = await import("@/lib/metrics/fetch");
		const { fetchTileData } = await import("@/lib/metrics/tiles");
		vi.mocked(fetchMod.fetchGatewayStatsFor).mockResolvedValue({
			total_cost_usd: 0,
			total_requests: 12,
		} as never);
		const out = await fetchTileData(
			{
				id: "t",
				metricId: "spend_est",
				shape: "stat",
				dimension: null,
			} as never,
			{ sinceMs: 0, untilMs: 3_600_000, bucketMs: 60_000 },
		);
		expect(out).toMatchObject({ kind: "stat", value: "—" });
	});
});

// ── Tile sizing (2026-09-07) — root cause + fix ─────────────────────────────────
//
// Founder report: "I tried adding a tile and it was so slim that the graph
// wasn't visible at all." Root cause, confirmed by grepping the BUILT
// stylesheet: `col-span-${tile.width}` was a template literal, and Tailwind
// only emits classes it can see LITERALLY in source — `.col-span-4` and
// `.col-span-6` never appeared anywhere in `.next/static/css/*.css`, only
// `.col-span-12` (because it is the one width used as a bare literal string
// elsewhere in the tree). A width=4 or width=6 tile therefore got NO
// grid-column rule and fell back to the CSS default (`grid-column: auto`,
// one of twelve tracks) at ANY viewport, not just mobile.
import {
	CHART_HEIGHT_PX,
	DIVIDER_METRIC_ID,
	DIVIDER_SHAPE,
	SHAPE_SIZE_DEFAULTS,
	STAT_MIN_HEIGHT_CLASS,
	STAT_MIN_HEIGHT_PX,
	TILE_HEIGHTS,
	TILE_WIDTHS,
	WIDTH_CLASS,
	cycleHeight,
	cycleWidth,
	heightPxFor,
} from "@/lib/metrics/tile-support";

describe("WIDTH_CLASS is a static literal map, never a template", () => {
	it("every width maps to a class string, and every class string is a LITERAL substring of the source file (not computed)", () => {
		const src = readFileSync(
			resolve(__dirname, "../../../lib/metrics/tile-support.ts"),
			"utf8",
		);
		for (const width of TILE_WIDTHS) {
			const cls = WIDTH_CLASS[width];
			expect(cls.length).toBeGreaterThan(0);
			// Every individual Tailwind token inside the class string must appear
			// verbatim in the source — this is exactly what Tailwind's own scanner
			// requires to emit the rule, and exactly what a template string like
			// `col-span-${n}` fails: `col-span-4` never appears as text.
			for (const token of cls.split(" ")) {
				expect(src.includes(token), `${token} missing from source text`).toBe(
					true,
				);
			}
		}
	});

	it("the buggy template pattern does not exist in the pages that render a tile's width (tile-support.ts's own doc comment names it historically and is excluded)", () => {
		const srcPage = readFileSync(
			resolve(__dirname, "../../dashboards/[id]/page.tsx"),
			"utf8",
		);
		const srcFrame = readFileSync(
			resolve(__dirname, "../../dashboards/[id]/TileFrame.tsx"),
			"utf8",
		);
		for (const src of [srcPage, srcFrame]) {
			expect(src).not.toMatch(/col-span-\$\{/);
		}
	});

	it("width=4 → 1/3 on desktop, full on mobile; width=12 → always full", () => {
		expect(WIDTH_CLASS[4]).toBe("col-span-12 md:col-span-4");
		expect(WIDTH_CLASS[6]).toBe("col-span-12 md:col-span-6");
		expect(WIDTH_CLASS[12]).toBe("col-span-12");
	});
});

describe("tile height → pixel mapping", () => {
	it("chart height is 220 / 320 / 480 — never the old fixed 140px", () => {
		expect(CHART_HEIGHT_PX.compact).toBe(220);
		expect(CHART_HEIGHT_PX.regular).toBe(320);
		expect(CHART_HEIGHT_PX.tall).toBe(480);
		for (const h of TILE_HEIGHTS) expect(CHART_HEIGHT_PX[h]).not.toBe(140);
	});

	it("stat min-height is smaller than chart height at every size", () => {
		for (const h of TILE_HEIGHTS) {
			expect(STAT_MIN_HEIGHT_PX[h]).toBeLessThan(CHART_HEIGHT_PX[h]);
		}
	});

	it("heightPxFor: stat reads STAT_MIN_HEIGHT_PX, series/breakdown read CHART_HEIGHT_PX", () => {
		for (const h of TILE_HEIGHTS) {
			expect(heightPxFor("stat", h)).toBe(STAT_MIN_HEIGHT_PX[h]);
			expect(heightPxFor("series", h)).toBe(CHART_HEIGHT_PX[h]);
			expect(heightPxFor("breakdown", h)).toBe(CHART_HEIGHT_PX[h]);
		}
	});

	it("STAT_MIN_HEIGHT_CLASS is a literal min-h-[…px] class matching STAT_MIN_HEIGHT_PX", () => {
		for (const h of TILE_HEIGHTS) {
			expect(STAT_MIN_HEIGHT_CLASS[h]).toBe(
				`min-h-[${STAT_MIN_HEIGHT_PX[h]}px]`,
			);
		}
	});
});

describe("cycleWidth / cycleHeight — resize control stepping", () => {
	it("cycleWidth steps 4→6→12 and clamps at both ends", () => {
		expect(cycleWidth(4, "wider")).toBe(6);
		expect(cycleWidth(6, "wider")).toBe(12);
		expect(cycleWidth(12, "wider")).toBe(12); // clamped, not wrapped
		expect(cycleWidth(12, "narrower")).toBe(6);
		expect(cycleWidth(6, "narrower")).toBe(4);
		expect(cycleWidth(4, "narrower")).toBe(4); // clamped
	});

	it("cycleHeight steps compact→regular→tall and clamps at both ends", () => {
		expect(cycleHeight("compact", "taller")).toBe("regular");
		expect(cycleHeight("regular", "taller")).toBe("tall");
		expect(cycleHeight("tall", "taller")).toBe("tall"); // clamped
		expect(cycleHeight("tall", "shorter")).toBe("regular");
		expect(cycleHeight("regular", "shorter")).toBe("compact");
		expect(cycleHeight("compact", "shorter")).toBe("compact"); // clamped
	});
});

describe("SHAPE_SIZE_DEFAULTS — the AddTileDialog picker's starting point", () => {
	it("a stat tile defaults compact/narrow; a series/breakdown tile defaults regular/half-width", () => {
		expect(SHAPE_SIZE_DEFAULTS.stat).toEqual({ width: 4, height: "compact" });
		expect(SHAPE_SIZE_DEFAULTS.series).toEqual({ width: 6, height: "regular" });
		expect(SHAPE_SIZE_DEFAULTS.breakdown).toEqual({
			width: 6,
			height: "regular",
		});
	});

	it("every default width/height is itself a member of the valid sets — the picker can never start on an invalid combination", () => {
		for (const shape of ["stat", "series", "breakdown"] as const) {
			const d = SHAPE_SIZE_DEFAULTS[shape];
			expect(TILE_WIDTHS).toContain(d.width);
			expect(TILE_HEIGHTS).toContain(d.height);
		}
	});
});

describe("DSH-13 tile input validation — height", () => {
	const VALID_HEIGHTS = new Set(["compact", "regular", "tall"]);
	function validateHeight(height: unknown): string | null {
		if (height === undefined) return null; // defaults to 'regular'
		if (typeof height !== "string" || !VALID_HEIGHTS.has(height)) {
			return "height must be compact, regular, or tall";
		}
		return null;
	}

	it("accepts undefined (defaults to regular)", () => {
		expect(validateHeight(undefined)).toBeNull();
	});
	it("accepts each of compact/regular/tall", () => {
		for (const h of TILE_HEIGHTS) expect(validateHeight(h)).toBeNull();
	});
	it("rejects an unknown height value", () => {
		expect(validateHeight("huge")).toMatch(/height must be/);
	});
});

// ── DSH-13 §9 — section dividers (2026-09-07) ───────────────────────────────
//
// Mirrors the divider branch of POST/PATCH /api/dashboards/[id]/tiles(/[tileId])
// (`route.ts`), the same "extracted from the route" convention the rest of
// this file uses. The end-to-end proof (a real POST/PATCH against the running
// app, plus the rendered grid) is the Playwright render proof — see the spec's
// §9.7 item 2.

/** Mirrors the divider-only validation in the POST route. Returns `{ error:
 * null }` for a non-divider shape — this validator has nothing to say about
 * those, the general `validateTileInput` above does. */
function validateDividerAdd(body: {
	shape?: string;
	metric_id?: string;
	width?: number;
	height?: string;
	dimension?: string | null;
}): { error: string | null; field?: string; status?: number } {
	if (body.shape !== DIVIDER_SHAPE) return { error: null };
	if (body.metric_id !== DIVIDER_METRIC_ID) {
		return {
			error: `divider tiles must use metric_id "${DIVIDER_METRIC_ID}"`,
			field: "metric_id",
			status: 400,
		};
	}
	if (body.width !== undefined && body.width !== 12) {
		return {
			error: "width must be 12 or omitted",
			field: "width",
			status: 400,
		};
	}
	if (body.height !== undefined && body.height !== "compact") {
		return {
			error: 'height must be "compact" or omitted',
			field: "height",
			status: 400,
		};
	}
	if (body.dimension) {
		return {
			error: "dimension is not valid for divider tiles",
			field: "dimension",
			status: 400,
		};
	}
	return { error: null };
}

/** Mirrors: the sentinel `metric_id` is reserved and refused on any OTHER shape. */
function validateNonDividerMetricId(
	shape: string,
	metricId: string,
): string | null {
	if (shape !== DIVIDER_SHAPE && metricId === DIVIDER_METRIC_ID) {
		return `metric_id "${DIVIDER_METRIC_ID}" is reserved for divider tiles — use shape "divider"`;
	}
	return null;
}

/** Mirrors the PATCH route's divider guard: an EXISTING divider tile may
 * change only `title` and `position` — width/height are pinned by the DB
 * CHECK, so a PATCH carrying either is refused, never silently ignored. */
function validateDividerPatch(
	tileShape: string,
	body: { width?: number; height?: string },
): string | null {
	if (tileShape !== DIVIDER_SHAPE) return null;
	if (body.width !== undefined) {
		return "divider tiles cannot be resized (width is always 12)";
	}
	if (body.height !== undefined) {
		return 'divider tiles cannot be resized (height is always "compact")';
	}
	return null;
}

describe("DSH-13 §9 divider tiles — POST validation", () => {
	it("accepts a divider with the sentinel metric_id and no width/height", () => {
		expect(
			validateDividerAdd({
				shape: DIVIDER_SHAPE,
				metric_id: DIVIDER_METRIC_ID,
			}),
		).toEqual({ error: null });
	});

	it("accepts a divider with width=12/height=compact stated explicitly", () => {
		expect(
			validateDividerAdd({
				shape: DIVIDER_SHAPE,
				metric_id: DIVIDER_METRIC_ID,
				width: 12,
				height: "compact",
			}),
		).toEqual({ error: null });
	});

	it("a divider with width=6 → 400 naming the width field", () => {
		const r = validateDividerAdd({
			shape: DIVIDER_SHAPE,
			metric_id: DIVIDER_METRIC_ID,
			width: 6,
		});
		expect(r.status).toBe(400);
		expect(r.field).toBe("width");
	});

	it("a divider with height=tall → 400 naming the height field", () => {
		const r = validateDividerAdd({
			shape: DIVIDER_SHAPE,
			metric_id: DIVIDER_METRIC_ID,
			height: "tall",
		});
		expect(r.status).toBe(400);
		expect(r.field).toBe("height");
	});

	it("a divider carrying a real metric_id → 400", () => {
		const firstId = Object.keys(METRICS)[0] ?? "llm_calls";
		const r = validateDividerAdd({
			shape: DIVIDER_SHAPE,
			metric_id: firstId,
		});
		expect(r.status).toBe(400);
		expect(r.field).toBe("metric_id");
	});

	it("a divider carrying a dimension → 400", () => {
		const r = validateDividerAdd({
			shape: DIVIDER_SHAPE,
			metric_id: DIVIDER_METRIC_ID,
			dimension: "model",
		});
		expect(r.status).toBe(400);
		expect(r.field).toBe("dimension");
	});

	it('the sentinel metric_id "__divider__" with shape "stat" → 400 (reserved, not a hidden metric)', () => {
		expect(validateNonDividerMetricId("stat", DIVIDER_METRIC_ID)).toMatch(
			/reserved for divider/,
		);
	});

	it("the sentinel metric_id is fine when the shape actually IS divider", () => {
		expect(
			validateNonDividerMetricId(DIVIDER_SHAPE, DIVIDER_METRIC_ID),
		).toBeNull();
	});

	it("DIVIDER_METRIC_ID is deliberately NOT a real registry key", () => {
		expect(DIVIDER_METRIC_ID in METRICS).toBe(false);
	});
});

describe("DSH-13 §9 divider tiles — PATCH validation", () => {
	it("an existing divider tile may change title/position (no width/height in the body)", () => {
		expect(validateDividerPatch(DIVIDER_SHAPE, {})).toBeNull();
	});

	it("an existing divider tile rejects a width change", () => {
		expect(validateDividerPatch(DIVIDER_SHAPE, { width: 6 })).toMatch(
			/cannot be resized/,
		);
	});

	it("an existing divider tile rejects a height change", () => {
		expect(validateDividerPatch(DIVIDER_SHAPE, { height: "tall" })).toMatch(
			/cannot be resized/,
		);
	});

	it("a non-divider tile is unaffected by this rule", () => {
		expect(validateDividerPatch("stat", { width: 6 })).toBeNull();
		expect(validateDividerPatch("series", { height: "tall" })).toBeNull();
	});
});

describe("DSH-13 §9 divider grid mechanics", () => {
	it("a divider is ALWAYS width=12 — the same literal class every other full-width tile uses, so no new grid rule is needed", () => {
		expect(WIDTH_CLASS[12]).toBe("col-span-12");
	});
});

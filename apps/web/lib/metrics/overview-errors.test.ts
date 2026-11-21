import { beforeEach, describe, expect, it, vi } from "vitest";

const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("@/lib/gateway", () => ({
	gatewayGet: (path: string) => get(path),
	GatewayError: class GatewayError extends Error {
		constructor(
			public status: number,
			message: string,
		) {
			super(message);
		}
	},
}));
import { GatewayError } from "@/lib/gateway";
import {
	fetchCostBreakdownFor,
	fetchGatewayStatsFor,
	fetchLatencyBreakdownFor,
	fetchSloSummary,
} from "./fetch";

const range = {
	sinceMs: Date.parse("2026-11-19T08:00:00Z"),
	untilMs: Date.parse("2026-11-19T14:00:00Z"),
	bucketMs: 300_000,
	permissionErrors: "throw" as const,
};
const reads = [
	["cost coverage", () => fetchCostBreakdownFor(range, "provider")],
	["gateway usage", () => fetchGatewayStatsFor(range)],
	["measured cache population", () => fetchLatencyBreakdownFor(range)],
	["health summary", () => fetchSloSummary(range)],
] as const;

beforeEach(() => get.mockReset());

describe.each(reads)("Overview %s read", (_name, read) => {
	it("preserves permission denial instead of representing it as absent measurements", async () => {
		const denied = new GatewayError(403, "Synthetic permission denial");
		get.mockRejectedValueOnce(denied);
		await expect(read()).rejects.toBe(denied);
	});

	it("keeps an unavailable gateway distinct from a measured zero", async () => {
		get.mockRejectedValueOnce(new GatewayError(503, "Synthetic unavailable"));
		await expect(read()).resolves.toBeNull();
	});

	it("does not hide unexpected programming failures", async () => {
		const unexpected = new TypeError("Synthetic malformed response");
		get.mockRejectedValueOnce(unexpected);
		await expect(read()).rejects.toBe(unexpected);
	});

	it("uses the selected UTC window without inventing a tenant query parameter", async () => {
		get.mockResolvedValueOnce(null);
		await read();
		const url = new URL(
			get.mock.calls[0]?.[0] ?? "",
			"https://synthetic.invalid",
		);
		expect(url.searchParams.get("since")).toBe("2026-11-19T08:00:00.000Z");
		expect(url.searchParams.get("until")).toBe("2026-11-19T14:00:00.000Z");
		expect(
			[...url.searchParams.keys()].some((key) => /tenant/i.test(key)),
		).toBe(false);
	});
});

it("leaves existing callers' unavailable contract unchanged unless explicitly requested", async () => {
	get.mockRejectedValueOnce(new GatewayError(403, "Synthetic denied"));
	await expect(
		fetchGatewayStatsFor({ ...range, permissionErrors: undefined }),
	).resolves.toBeNull();
});
